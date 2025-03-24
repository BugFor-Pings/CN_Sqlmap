
#!/usr/bin/env python

"""
版权 (c) 2006-2024 sqlmap 开发者 (https://sqlmap.org/)
查看文件 'LICENSE' 以获取复制许可
"""

from __future__ import division

import os
import re
import subprocess
import time

from lib.controller.action import action
from lib.controller.checks import checkConnection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkInternet
from lib.controller.checks import checkNullConnection
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkStability
from lib.controller.checks import checkWaf
from lib.controller.checks import heuristicCheckSqlInjection
from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import parseTargetUrl
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removePostHintPrefix
from lib.core.common import safeCSValue
from lib.core.common import showHttpErrorCodes
from lib.core.common import urldecode
from lib.core.common import urlencode
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.settings import ASP_NET_CONTROL_REGEX
from lib.core.settings import CSRF_TOKEN_PARAMETER_INFIXES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import EMPTY_FORM_FIELDS_REGEX
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HOST_ALIASES
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import LOW_TEXT_PERCENT
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv
from lib.utils.hash import crackHashFile

def _selectInjection():
    """
    注入位置、参数和类型的选择函数。
    """

    points = {}

    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype

        point = (place, parameter, ptype)

        if point not in points:
            points[point] = injection
        else:
            for key in points[point]:
                if key != 'data':
                    points[point][key] = points[point][key] or injection[key]
            points[point]['data'].update(injection['data'])

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = "发现多个注入点，请选择一个用于后续的注入:\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] 位置: %s, 参数: " % (i, place)
                message += "%s, 类型: %s" % (parameter, ptype)

                if i == 0:
                    message += " (默认)"

                message += "\n"

        message += "[q] 退出"
        choice = readInput(message, default='0').upper()

        if isDigit(choice) and int(choice) < len(kb.injections) and int(choice) >= 0:
            index = int(choice)
        elif choice == 'Q':
            raise SqlmapUserQuitException
        else:
            errMsg = "无效选择"
            raise SqlmapValueException(errMsg)

        kb.injection = kb.injections[index]

def _formatInjection(inj):
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else inj.place
    data = "参数: %s (%s)\n" % (inj.parameter, paramType)

    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
        payload = agent.adjustLateValues(sdata.payload)
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)($.+$)|(\blimit[^a-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[查询]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    类型: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    标题: %s\n" % title
        data += "    有效载荷: %s\n" % urldecode(payload, unsafe="&", spaceplus=(inj.place != PLACE.GET and kb.postSpaceToPlus))
        data += "    向量: %s\n\n" % vector if conf.verbose > 1 else "\n"

    return data

def _showInjections():
    if conf.wizard and kb.wizardMode:
        kb.wizardMode = False

    if kb.testQueryCount > 0:
        header = "sqlmap 识别到以下注入点，共进行了 %d 个 HTTP(s) 请求" % kb.testQueryCount
    else:
        header = "sqlmap 从存储的会话中恢复了以下注入点"

    if conf.api:
        conf.dumper.string("", {"url": conf.url, "query": conf.parameters.get(PLACE.GET), "data": conf.parameters.get(PLACE.POST)}, content_type=CONTENT_TYPE.TARGET)
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        data = "".join(set(_formatInjection(_) for _ in kb.injections)).rstrip("\n")
        conf.dumper.string(header, data)

def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = "你想用随机值填充空字段吗? [Y/n] "

        if readInput(message, default='Y', boolean=True):
            for match in re.finditer(EMPTY_FORM_FIELDS_REGEX, retVal):
                item = match.group("result")
                if not any(_ in item for _ in IGNORE_PARAMETERS) and not re.search(ASP_NET_CONTROL_REGEX, item):
                    newValue = randomStr() if not re.search(r"^id|id$", item, re.I) else randomInt()
                    if item[-1] == DEFAULT_GET_POST_DELIMITER:
                        retVal = retVal.replace(item, "%s%s%s" % (item[:-1], newValue, DEFAULT_GET_POST_DELIMITER))
                    else:
                        retVal = retVal.replace(item, "%s%s" % (item, newValue))

    return retVal

def _saveToHashDB():
    injections = hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True)
    if not isListLike(injections):
        injections = []
    injections.extend(_ for _ in kb.injections if _ and _.place is not None and _.parameter is not None)

    _ = dict()
    for injection in injections:
        key = (injection.place, injection.parameter, injection.ptype)
        if key not in _:
            _[key] = injection
        else:
            _[key].data.update(injection.data)
    hashDBWrite(HASHDB_KEYS.KB_INJECTIONS, list(_.values()), True)

    _ = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True)
    hashDBWrite(HASHDB_KEYS.KB_ABS_FILE_PATHS, kb.absFilePaths | (_ if isinstance(_, set) else set()), True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_CHARS):
        hashDBWrite(HASHDB_KEYS.KB_CHARS, kb.chars, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS):
        hashDBWrite(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, kb.dynamicMarkings, True)

def _saveToResultsFile():
    if not conf.resultsFP:
        return

    results = {}
    techniques = dict((_[1], _[0]) for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE))

    for injection in kb.injections + kb.falsePositives:
        if injection.place is None or injection.parameter is None:
            continue

        key = (injection.place, injection.parameter, ';'.join(injection.notes))
        if key not in results:
            results[key] = []

        results[key].extend(list(injection.data.keys()))

    try:
        for key, value in results.items():
            place, parameter, notes = key
            line = "%s,%s,%s,%s,%s%s" % (safeCSValue(kb.originalUrls.get(conf.url) or conf.url), place, parameter, "".join(techniques[_][0].upper() for _ in sorted(value)), notes, os.linesep)
            conf.resultsFP.write(line)

        conf.resultsFP.flush()
    except IOError as ex:
        errMsg = "无法写入结果文件 '%s' ('%s'). " % (conf.resultsFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

@stackedmethod
def start():
    """
    此函数调用一个函数，对 URL 的稳定性以及所有 GET, POST, Cookie 和 User-Agent 参数进行检查，以检查它们是否是动态的并且受到 SQL 注入的影响
    """

    if conf.hashFile:
        crackHashFile(conf.hashFile)

    if conf.direct:
        initTargetEnv()
        setupTargetEnv()
        action()
        return True

    if conf.url and not any((conf.forms, conf.crawlDepth)):
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie, None))

    if conf.configFile and not kb.targets:
        errMsg = "您没有正确编辑配置文件，请设置 "
        errMsg += "目标 URL、目标列表或 Google Dork"
        logger.error(errMsg)
        return False

    if kb.targets and isListLike(kb.targets) and len(kb.targets) > 1:
        infoMsg = "发现总共 %d 个目标" % len(kb.targets)
        logger.info(infoMsg)

    targetCount = 0
    initialHeaders = list(conf.httpHeaders)

    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        targetCount += 1

        try:
            if conf.checkInternet:
                infoMsg = "检查互联网连接"
                logger.info(infoMsg)

                if not checkInternet():
                    warnMsg = "[%s] [WARNING] 未检测到连接" % time.strftime("%X")
                    dataToStdout(warnMsg)

                    valid = False
                    for _ in xrange(conf.retries):
                        if checkInternet():
                            valid = True
                            break
                        else:
                            dataToStdout('.')
                            time.sleep(5)

                    if not valid:
                        errMsg = "请检查您的互联网连接并重新运行"
                        raise SqlmapConnectionException(errMsg)
                    else:
                        dataToStdout("\n")

            conf.url = targetUrl
            conf.method = targetMethod.upper().strip() if targetMethod else targetMethod
            conf.data = targetData
            conf.cookie = targetCookie
            conf.httpHeaders = list(initialHeaders)
            conf.httpHeaders.extend(targetHeaders or [])

            if conf.randomAgent or conf.mobile:
                for header, value in initialHeaders:
                    if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                        conf.httpHeaders.append((header, value))
                        break

            if conf.data:
                # 注意：明确 URL 编码 __ ASP(.NET) 参数（例如，避免 Base64 编码的 '+' 字符问题） - 在网页浏览器中的标准程序
                conf.data = re.sub(r"\b(__\w+)=([^&]+)", lambda match: "%s=%s" % (match.group(1), urlencode(match.group(2), safe='%')), conf.data)

            conf.httpHeaders = [conf.httpHeaders[i] for i in xrange(len(conf.httpHeaders)) if conf.httpHeaders[i][0].upper() not in (__[0].upper() for __ in conf.httpHeaders[i + 1:])]

            initTargetEnv()
            parseTargetUrl()

            testSqlInj = False

            if PLACE.GET in conf.parameters and not any((conf.data, conf.testParameter)):
                for parameter in re.findall(r"([^=]+)=([^%s]+%s?|\Z)" % (re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER, re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER), conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter[0])

                    if paramKey not in kb.testedParams:
                        testSqlInj = True
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)
                if paramKey not in kb.testedParams:
                    testSqlInj = True

            if testSqlInj and conf.hostname in kb.vulnHosts:
                if kb.skipVulnHost is None:
                    message = "SQL 注入漏洞已经被检测到 "
                    message += "针对 '%s'. 您想跳过 " % conf.hostname
                    message += "随后对它的进一步测试吗? [Y/n]"

                    kb.skipVulnHost = readInput(message, default='Y', boolean=True)

                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:
                infoMsg = "跳过 '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                if conf.forms and conf.method:
                    message = "[%d/%s] 表单:\n%s %s" % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', conf.method, targetUrl)
                else:
                    message = "[%d/%s] URL:\n%s %s" % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', HTTPMETHOD.GET, targetUrl)

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += "\n%s 数据: %s" % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "") is None else conf.data)

                if conf.forms and conf.method:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\n你想测试这个表单吗? [Y/n/q] "
                    choice = readInput(message, default='Y').upper()

                    if choice == 'N':
                        continue
                    elif choice == 'Q':
                        break
                    else:
                        if conf.method != HTTPMETHOD.GET:
                            message = "编辑 %s 数据 [默认: %s]%s: " % (conf.method, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "None") is None else conf.data, " (警告: 检测到空字段)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        else:
                            if '?' in targetUrl:
                                firstPart, secondPart = targetUrl.split('?', 1)
                                message = "编辑 GET 数据 [默认: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()

                else:
                    if not conf.scope:
                        message += "\n你想测试这个 URL 吗? [Y/n/q]"
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            dataToStdout(os.linesep)
                            continue
                        elif choice == 'Q':
                            break
                    else:
                        pass

                    infoMsg = "正在测试 URL '%s'" % targetUrl
                    logger.info(infoMsg)

            setupTargetEnv()

            if not checkConnection(suppressOutput=conf.forms):
                continue

            if conf.rParam and kb.originalPage:
                kb.randomPool = dict([_ for _ in kb.randomPool.items() if isinstance(_[1], list)])

                for match in re.finditer(r"(?si)<select[^>]+\bname\s*=\s*[\"']([^\"']+)(.+?)</select>", kb.originalPage):
                    name, _ = match.groups()
                    options = tuple(re.findall(r"<option[^>]+\bvalue\s*=\s*[\"']([^\"']+)", _))
                    if options:
                        kb.randomPool[name] = options

            checkWaf()

            if conf.nullConnection:
                checkNullConnection()

            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) and (kb.injection.place is None or kb.injection.parameter is None):
                if not any((conf.string, conf.notString, conf.regexp)) and PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique:
                    # 注意：这不再需要，只是留着以便在页面不稳定的情况下给用户显示
                    checkStability()

                # 对可测试参数列表进行小的优先级排序重排
                parameters = list(conf.parameters.keys())

                # 测试列表的顺序（从第一个到最后一个）
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                for place in parameters:
                    # 仅当 --level >= 3 时测试 User-Agent 和 Referer 头
                    skip = (place == PLACE.USER_AGENT and (kb.testOnlyCustom or conf.level < 3))
                    skip |= (place == PLACE.REFERER and (kb.testOnlyCustom or conf.level < 3))

                    # --param-filter
                    skip |= (len(conf.paramFilter) > 0 and place.upper() not in conf.paramFilter)

                    # 仅当 --level >= 5 时测试 Host 头
                    skip |= (place == PLACE.HOST and (kb.testOnlyCustom or conf.level < 5))

                    # 仅当 --level >= 2 时测试 Cookie 头
                    skip |= (place == PLACE.COOKIE and (kb.testOnlyCustom or conf.level < 2))

                    skip |= (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.COOKIE and intersect(PLACE.COOKIE, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.HOST and intersect(PLACE.HOST, conf.skip, True) not in ([], None))

                    skip &= not (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.HOST and intersect(HOST_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.COOKIE and intersect((PLACE.COOKIE,), conf.testParameter, True))

                    if skip:
                        continue

                    if place not in conf.paramDict or place not in conf.parameters:
                        continue

                    paramDict = conf.paramDict[place]

                    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

                    for parameter, value in paramDict.items():
                        if not proceed:
                            break

                        kb.vainRun = False
                        testSqlInj = True
                        paramKey = (conf.hostname, conf.path, place, parameter)

                        if kb.processUserMarks:
                            if testSqlInj and place not in (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI):
                                if kb.processNonCustom is None:
                                    message = "发现其他非自定义参数. "
                                    message += "你想也处理这些吗? [Y/n/q] "
                                    choice = readInput(message, default='Y').upper()

                                    if choice == 'Q':
                                        raise SqlmapUserQuitException
                                    else:
                                        kb.processNonCustom = choice == 'Y'

                                if not kb.processNonCustom:
                                    infoMsg = "跳过 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)
                                    continue

                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "跳过之前处理过的 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif any(_ in conf.testParameter for _ in (parameter, removePostHintPrefix(parameter))):
                            pass

                        elif parameter in conf.rParam:
                            testSqlInj = False

                            infoMsg = "跳过随机化 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.skip or kb.postHint and parameter.split(' ')[-1] in conf.skip:
                            testSqlInj = False

                            infoMsg = "跳过 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.paramExclude and (re.search(conf.paramExclude, parameter, re.I) or kb.postHint and re.search(conf.paramExclude, parameter.split(' ')[-1], re.I) or re.search(conf.paramExclude, place, re.I)):
                            testSqlInj = False

                            infoMsg = "跳过 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.csrfToken and re.search(conf.csrfToken, parameter, re.I):
                            testSqlInj = False

                            infoMsg = "跳过反 CSRF 令牌参数 '%s'" % parameter
                            logger.info(infoMsg)

                        # 对于 --level < 4 的情况，忽略类似会话的参数
                        elif conf.level < 4 and (parameter.upper() in IGNORE_PARAMETERS or any(_ in parameter.lower() for _ in CSRF_TOKEN_PARAMETER_INFIXES) or parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX)):
                            testSqlInj = False

                            infoMsg = "忽略 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique or conf.skipStatic:
                            check = checkDynParam(place, parameter, value)

                            if not check:
                                warnMsg = "%s参数 '%s' 不似乎是动态的" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.warning(warnMsg)

                                if conf.skipStatic:
                                    infoMsg = "跳过静态 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)

                                    testSqlInj = False
                            else:
                                infoMsg = "%s参数 '%s' 看起来是动态的" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:
                            try:
                                if place == PLACE.COOKIE:
                                    pushValue(kb.mergeCookies)
                                    kb.mergeCookies = False

                                check = heuristicCheckSqlInjection(place, parameter)

                                if check != HEURISTIC_TEST.POSITIVE:
                                    if conf.smart or (kb.ignoreCasted and check == HEURISTIC_TEST.CASTED):
                                        infoMsg = "跳过 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                        logger.info(infoMsg)
                                        continue

                                infoMsg = "正在测试 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                                injection = checkSqlInjection(place, parameter, value)
                                proceed = not kb.endDetection
                                injectable = False

                                if getattr(injection, "place", None) is not None:
                                    if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE in injection.notes:
                                        kb.falsePositives.append(injection)
                                    else:
                                        injectable = True

                                        kb.injections.append(injection)

                                        if not kb.alerted:
                                            if conf.alert:
                                                infoMsg = "执行警报命令 ('%s')" % conf.alert
                                                logger.info(infoMsg)
                                                try:
                                                    process = subprocess.Popen(conf.alert, shell=True)
                                                    process.wait()
                                                except Exception as ex:
                                                    errMsg = "执行 '%s' 时发生错误 ('%s')" % (conf.alert, getSafeExString(ex))
                                                    logger.error(errMsg)

                                            kb.alerted = True

                                        # 在用户想结束检测阶段（Ctrl+C）时
                                        if not proceed:
                                            break

                                        msg = "%s参数 '%s' " % ("%s " % injection.place if injection.place != injection.parameter else "", injection.parameter)
                                        msg += "是有漏洞的。您想继续测试其他参数吗（如果有的话）? [y/N] "

                                        if not readInput(msg, default='N', boolean=True):
                                            proceed = False
                                            paramKey = (conf.hostname, conf.path, None, None)
                                            kb.testedParams.add(paramKey)

                                if not injectable:
                                    warnMsg = "%s参数 '%s' 似乎不可注入" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.warning(warnMsg)

                            finally:
                                if place == PLACE.COOKIE:
                                    kb.mergeCookies = popValue()

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "未在提供的数据中找到可测试的参数 "
                    errMsg += "(例如，在 'www.site.com/index.php?id=1' 中的 GET 参数 'id')"
                    if kb.originalPage:
                        advice = []
                        if not conf.forms and re.search(r"<form", kb.originalPage) is not None:
                            advice.append("--forms")
                        if not conf.crawlDepth and re.search(r"href=[\"']/?\w", kb.originalPage) is not None:
                            advice.append("--crawl=2")
                        if advice:
                            errMsg += ". 您建议以 '%s' 重新运行" % ' '.join(advice)
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "所有测试的参数似乎不可注入。"

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " 如果您希望进行更多测试，请尝试提高 '--level'/'--risk' 选项的值。"

                    if isinstance(conf.technique, list) and len(conf.technique) < 5:
                        errMsg += " 重新运行时不提供 '--technique' 选项。"

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " 如果目标页面的文本内容比例较低，您可以使用开关 '--text-only' "
                            errMsg += "尝试一次 (~%.2f%% 的 " % percent
                            errMsg += "页面内容是文本)。"
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " 请重试使用开关 '--text-only' "
                            errMsg += "(以及 --technique=BU) 因为此情况 "
                            errMsg += "看起来是一个完美的候选 "
                            errMsg += "(低文本内容以及未能检测到至少一个动态参数)。"

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += " 由于启发式测试结果为正，您被强烈建议继续进行测试。"

                    if conf.string:
                        errMsg += " 同样，您可以尝试通过提供一个 "
                        errMsg += "有效值给 '--string' 选项来重新运行，因为您选择的字符串 "
                        errMsg += "可能并不匹配 "
                        errMsg += "仅仅属于真实响应。"
                    elif conf.regexp:
                        errMsg += " 同样，您可以尝试通过提供一个 "
                        errMsg += "有效值给 '--regexp' 选项来重新运行，因为您选择的正则表达式 "
                        errMsg += "可能并不匹配 "
                        errMsg += "仅仅属于真实响应。"

                    if not conf.tamper:
                        errMsg += " 如果您怀疑有某种保护机制 "
                        errMsg += "存在（例如 WAF），也许您可以尝试使用 "
                        errMsg += "选项 '--tamper'（例如，'--tamper=space2comment'）"

                        if not conf.randomAgent:
                            errMsg += " 和/或切换 '--random-agent'"

                    raise SqlmapNotVulnerableException(errMsg.rstrip('.'))
            else:
                # 刷新标志
                kb.testMode = False

                _saveToResultsFile()
                _saveToHashDB()
                _showInjections()
                _selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "您想利用此 SQL 注入吗? [Y/n] "
                    condition = readInput(message, default='Y', boolean=True)
                else:
                    condition = True

                if condition:
                    action()

        except KeyboardInterrupt:
            if kb.lastCtrlCTime and (time.time() - kb.lastCtrlCTime < 1):
                kb.multipleCtrlC = True
                raise SqlmapUserQuitException("用户中止（Ctrl+C 被按下多次）")

            kb.lastCtrlCTime = time.time()

            if conf.multipleTargets:
                warnMsg = "用户在多目标模式中中止"
                logger.warning(warnMsg)

                message = "您想跳到列表中的下一个目标吗? [Y/n/q]"
                choice = readInput(message, default='Y').upper()

                if choice == 'N':
                    return False
                elif choice == 'Q':
                    raise SqlmapUserQuitException
            else:
                raise

        except SqlmapSkipTargetException:
            pass

        except SqlmapUserQuitException:
            raise

        except SqlmapSilentQuitException:
            raise

        except SqlmapBaseException as ex:
            errMsg = getSafeExString(ex)

            if conf.multipleTargets:
                _saveToResultsFile()

                errMsg += ", 跳过下一个目标"
                logger.error(errMsg.lstrip(", "))
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = "目标似乎有最大连接数限制"
                logger.warning(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("获取的数据已记录到 '%s' 下的文本文件中" % conf.outputPath)

    if conf.multipleTargets:
        if conf.resultsFile:
            infoMsg = "您可以在 CSV 文件 '%s' 中找到多目标模式扫描的结果" % conf.resultsFile
            logger.info(infoMsg)

    return True
