#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
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
    Selection function for injection place, parameters and type.
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
        message = "有多个注射点，请选择 "
        message += "用于以下注射：\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] 位置: %s,参数: " % (i, place)
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
            errMsg = "无效的选择"
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
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^a-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    类型: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    标题: %s\n" % title
        data += "    Payload: %s\n" % urldecode(payload, unsafe="&", spaceplus=(inj.place != PLACE.GET and kb.postSpaceToPlus))
        data += "    向量/载体: %s\n\n" % vector if conf.verbose > 1 else "\n"

    return data

def _showInjections():
    if conf.wizard and kb.wizardMode:
        kb.wizardMode = False

    if kb.testQueryCount > 0:
        header = "sqlmap确定了以下注射点 "
        header += "总共 %d 个HTTP请求" % kb.testQueryCount
    else:
        header = "sqlmap从存储的会话恢复了以下注入点"

    if conf.api:
        conf.dumper.string("", {"url": conf.url, "query": conf.parameters.get(PLACE.GET), "data": conf.parameters.get(PLACE.POST)}, content_type=CONTENT_TYPE.TARGET)
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        data = "".join(set(_formatInjection(_) for _ in kb.injections)).rstrip("\n")
        conf.dumper.string(header, data)

    if conf.tamper:
        warnMsg = "tamper脚本所做的内容不会 "
        warnMsg += "显示在有效载荷内容中"
        logger.warning(warnMsg)

    if conf.hpp:
        warnMsg = "HTTP参数污染所做的内容不会 "
        warnMsg += "显示在有效载荷内容中"
        logger.warning(warnMsg)

def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = "是否要用随机值填充空白字段？ [Y/n] "

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
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
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
        errMsg += "目标URL、目标列表或google dork"
        logger.error(errMsg)
        return False

    if kb.targets and isListLike(kb.targets) and len(kb.targets) > 1:
        infoMsg = "共找到 %d 个目标" % len(kb.targets)
        logger.info(infoMsg)

    targetCount = 0
    initialHeaders = list(conf.httpHeaders)

    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        targetCount += 1

        try:
            if conf.checkInternet:
                infoMsg = "检查Internet连接"
                logger.info(infoMsg)

                if not checkInternet():
                    warnMsg = "[%s] [警告] 未检测到连接" % time.strftime("%X")
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
                        errMsg = "请检查Internet连接并重新运行"
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
                # Note: explicitly URL encode __ ASP(.NET) parameters (e.g. to avoid problems with Base64 encoded '+' character) - standard procedure in web browsers
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
                    message = "已检测到SQL注入漏洞 "
                    message += "针对 '%s'. 是否要跳过 " % conf.hostname
                    message += "涉及它的进一步测试？ [Y/n]"

                    kb.skipVulnHost = readInput(message, default='Y', boolean=True)

                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:
                infoMsg = "跳过 '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                if conf.forms and conf.method:
                    message = "[%d/%s] Form:\n%s %s" % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', conf.method, targetUrl)
                else:
                    message = "[%d/%s] URL:\n%s %s" % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', HTTPMETHOD.GET, targetUrl)

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += "\n%s data: %s" % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "") is None else conf.data)

                if conf.forms and conf.method:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\n是否要测试此表单？ [Y/n/q] "
                    choice = readInput(message, default='Y').upper()

                    if choice == 'N':
                        continue
                    elif choice == 'Q':
                        break
                    else:
                        if conf.method != HTTPMETHOD.GET:
                            message = "编辑 %s 数据 [默认值: %s]%s: " % (conf.method, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "None") is None else conf.data, " (Warning: blank fields detected)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        else:
                            if '?' in targetUrl:
                                firstPart, secondPart = targetUrl.split('?', 1)
                                message = "编辑GET数据 [默认值: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()

                else:
                    if not conf.scope:
                        message += "\n是否要测试此URL？ [Y/n/q]"
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            dataToStdout(os.linesep)
                            continue
                        elif choice == 'Q':
                            break
                    else:
                        pass

                    infoMsg = "测试URL '%s'" % targetUrl
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
                    # NOTE: this is not needed anymore, leaving only to display
                    # a warning message to the user in case the page is not stable
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list
                parameters = list(conf.parameters.keys())

                # Order of testing list (first to last)
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                for place in parameters:
                    # Test User-Agent and Referer headers only if
                    # --level >= 3
                    skip = (place == PLACE.USER_AGENT and (kb.testOnlyCustom or conf.level < 3))
                    skip |= (place == PLACE.REFERER and (kb.testOnlyCustom or conf.level < 3))

                    # --param-filter
                    skip |= (len(conf.paramFilter) > 0 and place.upper() not in conf.paramFilter)

                    # Test Host header only if
                    # --level >= 5
                    skip |= (place == PLACE.HOST and (kb.testOnlyCustom or conf.level < 5))

                    # Test Cookie header only if --level >= 2
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

                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "跳过以前处理的 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
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

                        elif conf.paramExclude and (re.search(conf.paramExclude, parameter, re.I) or kb.postHint and re.search(conf.paramExclude, parameter.split(' ')[-1], re.I)):
                            testSqlInj = False

                            infoMsg = "跳过 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.csrfToken and re.search(conf.csrfToken, parameter, re.I):
                            testSqlInj = False

                            infoMsg = "跳过反CSRF令牌参数 '%s'" % parameter
                            logger.info(infoMsg)

                        # Ignore session-like parameters for --level < 4
                        elif conf.level < 4 and (parameter.upper() in IGNORE_PARAMETERS or any(_ in parameter.lower() for _ in CSRF_TOKEN_PARAMETER_INFIXES) or parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX)):
                            testSqlInj = False

                            infoMsg = "忽略 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique or conf.skipStatic:
                            check = checkDynParam(place, parameter, value)

                            if not check:
                                warnMsg = "%s参数 '%s' 看起来不是动态的" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.warning(warnMsg)

                                if conf.skipStatic:
                                    infoMsg = "跳过静态 %s参数 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)

                                    testSqlInj = False
                            else:
                                infoMsg = "%s参数 '%s' 似乎是动态的" % ("%s " % paramType if paramType != parameter else "", parameter)
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

                                infoMsg = "在 %s参数上测试SQL注入 '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
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
                                                infoMsg = "正在执行警告shell命令 ('%s')" % conf.alert
                                                logger.info(infoMsg)
                                                try:
                                                    process = subprocess.Popen(conf.alert, shell=True)
                                                    process.wait()
                                                except Exception as ex:
                                                    errMsg = "执行时出错 '%s' ('%s')" % (conf.alert, getSafeExString(ex))
                                                    logger.error(errMsg)

                                            kb.alerted = True

                                        # In case when user wants to end detection phase (Ctrl+C)
                                        if not proceed:
                                            break

                                        msg = "%s参数 '%s' " % ("%s " % injection.place if injection.place != injection.parameter else "", injection.parameter)
                                        msg += "是脆弱的。你想继续测试其他（如果有的话）吗？ [y/N] "

                                        if not readInput(msg, default='N', boolean=True):
                                            proceed = False
                                            paramKey = (conf.hostname, conf.path, None, None)
                                            kb.testedParams.add(paramKey)

                                if not injectable:
                                    warnMsg = "%s参数 '%s' 似乎不可注射" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.warning(warnMsg)

                            finally:
                                if place == PLACE.COOKIE:
                                    kb.mergeCookies = popValue()

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "在提供的数据中找不到用于测试的参数 "
                    errMsg += "(例子 GET 参数 'id' 在 'www.site.com/index.php?id=1')"
                    if kb.originalPage:
                        advice = []
                        if not conf.forms and re.search(r"<form", kb.originalPage) is not None:
                            advice.append("--forms")
                        if not conf.crawlDepth and re.search(r"href=[\"']/?\w", kb.originalPage) is not None:
                            advice.append("--crawl=2")
                        if advice:
                            errMsg += ". 建议您重新运行 '%s'" % ' '.join(advice)
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "所有测试参数似乎都不是可注射的"

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " 尝试增加'--level'/'--risk'选项的值 "
                        errMsg += "如果您希望执行更多测试"

                    if isinstance(conf.technique, list) and len(conf.technique) < 5:
                        errMsg += " 在不提供选项'--technique'的情况下重新运行"

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " 您可以使用参数 '--text-only' "
                            errMsg += "如果目标页的百分比较低 "
                            errMsg += "文本内容的 (~%.2f%% of " % percent
                            errMsg += "页面内容为文本)."
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " 请使用交换机重试 '--text-only' "
                            errMsg += "(连同 --technique=BU) 在这种情况下 "
                            errMsg += "看起来是个完美的人选 "
                            errMsg += "(文本内容低，且无法使用 "
                            errMsg += "至少检测到 "
                            errMsg += "一个动态参数)."

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += " 当启发式测试结果为阳性时 "
                        errMsg += "强烈建议继续进行测试"

                    if conf.string:
                        errMsg += "此外，您可以尝试通过提供 "
                        errMsg += "选项'--string'的有效值可能是 "
                        errMsg += "选择的不匹配 "
                        errMsg += "完全正确的回答."
                    elif conf.regexp:
                        errMsg += " 此外，您可以尝试通过提供"
                        errMsg += "选项'--regexp'的有效值可能是 "
                        errMsg += "您选择的表达式"
                        errMsg += "不完全匹配True响应."

                    if not conf.tamper:
                        errMsg += " 如果你怀疑有某种保护机制 "
                        errMsg += "卷入的(例如 WAF) 也许你可以尝试使用 "
                        errMsg += "选项 '--tamper' (例子 '--tamper=space2comment')"

                        if not conf.randomAgent:
                            errMsg += " 和/或者 开关 '--random-agent'"

                    raise SqlmapNotVulnerableException(errMsg.rstrip('.'))
            else:
                # Flush the flag
                kb.testMode = False

                _saveToResultsFile()
                _saveToHashDB()
                _showInjections()
                _selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "是否要利用此SQL注入？[Y/n] "
                    condition = readInput(message, default='Y', boolean=True)
                else:
                    condition = True

                if condition:
                    action()

        except KeyboardInterrupt:
            if kb.lastCtrlCTime and (time.time() - kb.lastCtrlCTime < 1):
                kb.multipleCtrlC = True
                raise SqlmapUserQuitException("用户已中止（多次按下Ctrl+C）")

            kb.lastCtrlCTime = time.time()

            if conf.multipleTargets:
                warnMsg = "用户在多目标模式下中止"
                logger.warning(warnMsg)

                message = "是否要跳到列表中的下一个目标？[Y/n/q]"
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

                errMsg += ", 跳到下一个目标"
                logger.error(errMsg.lstrip(", "))
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = "看来目标 "
                warnMsg += "具有最大连接数 "
                warnMsg += "限制"
                logger.warning(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("提取的数据记录到下面的文本文件 '%s'" % conf.outputPath)

    if conf.multipleTargets:
        if conf.resultsFile:
            infoMsg = "您可以在多个目标中找到扫描结果 "
            infoMsg += "CSV文件中的模式 '%s'" % conf.resultsFile
            logger.info(infoMsg)

    return True
