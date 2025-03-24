
#!/usr/bin/env python

"""
版权所有 (c) 2006-2024 sqlmap 开发者 (https://sqlmap.org/)
见文件 'LICENSE' 获取复制权限
"""

import functools
import os
import re
import subprocess
import sys
import tempfile
import time

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import intersect
from lib.core.common import isNumPosStrValue
from lib.core.common import normalizeUnicode
from lib.core.common import openFile
from lib.core.common import paramToDict
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removePostHintPrefix
from lib.core.common import resetCookieJar
from lib.core.common import safeStringFormat
from lib.core.common import unArrayizeValue
from lib.core.common import urldecode
from lib.core.compat import xrange
from lib.core.convert import decodeBase64
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import paths
from lib.core.datatype import InjectionDict
from lib.core.dicts import DBMS_DICT
from lib.core.dump import dumper
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.option import _setAuthCred
from lib.core.option import _setDBMS
from lib.core.option import _setKnowledgeBaseAttributes
from lib.core.settings import ARRAY_LIKE_RECOGNITION_REGEX
from lib.core.settings import ASTERISK_MARKER
from lib.core.settings import CSRF_TOKEN_PARAMETER_INFIXES
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import HOST_ALIASES
from lib.core.settings import INJECT_HERE_REGEX
from lib.core.settings import JSON_LIKE_RECOGNITION_REGEX
from lib.core.settings import JSON_RECOGNITION_REGEX
from lib.core.settings import MULTIPART_RECOGNITION_REGEX
from lib.core.settings import PROBLEMATIC_CUSTOM_INJECTION_PATTERNS
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import RESTORE_MERGED_OPTIONS
from lib.core.settings import RESULTS_FILE_FORMAT
from lib.core.settings import SESSION_SQLITE_FILE
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import XML_RECOGNITION_REGEX
from lib.core.threads import getCurrentThreadData
from lib.utils.hashdb import HashDB
from thirdparty import six
from thirdparty.odict import OrderedDict
from thirdparty.six.moves import urllib as _urllib

def _setRequestParams():
    """
    检查并设置参数，并对HTTP POST方法的“data”选项执行检查。
    """

    if conf.direct:
        conf.parameters[None] = "直接连接"
        return

    hintNames = []
    testableParameters = False

    # 对GET参数执行检查
    if conf.parameters.get(PLACE.GET):
        parameters = conf.parameters[PLACE.GET]
        paramDict = paramToDict(PLACE.GET, parameters)

        if paramDict:
            conf.paramDict[PLACE.GET] = paramDict
            testableParameters = True

    # 对POST参数执行检查
    if conf.method == HTTPMETHOD.POST and conf.data is None:
        logger.warning("检测到空的POST主体")
        conf.data = ""

    if conf.data is not None:
        conf.method = conf.method or HTTPMETHOD.POST

        def process(match, repl):
            retVal = match.group(0)

            if not (conf.testParameter and match.group("name") not in (removePostHintPrefix(_) for _ in conf.testParameter)) and match.group("name") == match.group("name").strip('\\'):
                retVal = repl
                while True:
                    _ = re.search(r"\\g<([^>]+)>", retVal)
                    if _:
                        try:
                            retVal = retVal.replace(_.group(0), match.group(int(_.group(1)) if _.group(1).isdigit() else _.group(1)))
                        except IndexError:
                            break
                    else:
                        break
                if kb.customInjectionMark in retVal:
                    hintNames.append((retVal.split(kb.customInjectionMark)[0], match.group("name").strip('"\'') if kb.postHint == POST_HINT.JSON_LIKE else match.group("name")))

            return retVal

        if kb.processUserMarks is None and kb.customInjectionMark in conf.data:
            message = "在%s中发现自定义注入标记 ('%s') " % (conf.method, kb.customInjectionMark)
            message += "主体。您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            else:
                kb.processUserMarks = choice == 'Y'

                if kb.processUserMarks:
                    kb.testOnlyCustom = True

        if re.search(JSON_RECOGNITION_REGEX, conf.data):
            message = "在%s主体中发现JSON数据。 " % conf.method
            message += "您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.JSON
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', functools.partial(process, repl=r'\g<1>%s"' % kb.customInjectionMark), conf.data)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*")"', functools.partial(process, repl=r'\g<1>%s"' % kb.customInjectionMark), conf.data)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', functools.partial(process, repl=r'\g<1>\g<3>%s' % kb.customInjectionMark), conf.data)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)((true|false|null))\b', functools.partial(process, repl=r'\g<1>\g<3>%s' % kb.customInjectionMark), conf.data)
                    for match in re.finditer(r'(?P<name>[^"]+)"\s*:\s*$([^$]+)\]', conf.data):
                        if not (conf.testParameter and match.group("name") not in conf.testParameter):
                            _ = match.group(2)
                            if kb.customInjectionMark not in _:  # 注意: 仅适用于未处理的(简单)形式即非关联数组 (例如: [1,2,3])
                                _ = re.sub(r'("[^"]+)"', r'\g<1>%s"' % kb.customInjectionMark, _)
                                _ = re.sub(r'(\A|,|\s+)(-?\d[\d\.]*\b)', r'\g<0>%s' % kb.customInjectionMark, _)
                                conf.data = conf.data.replace(match.group(0), match.group(0).replace(match.group(2), _))

        elif re.search(JSON_LIKE_RECOGNITION_REGEX, conf.data):
            message = "在%s主体中发现类JSON数据。 " % conf.method
            message += "您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.JSON_LIKE
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    if '"' in conf.data:
                        conf.data = re.sub(r'((?P<name>"[^"]+"|\w+)\s*:\s*"[^"]+)"', functools.partial(process, repl=r'\g<1>%s"' % kb.customInjectionMark), conf.data)
                        conf.data = re.sub(r'((?P<name>"[^"]+"|\w+)\s*:\s*)(-?\d[\d\.]*\b)', functools.partial(process, repl=r'\g<0>%s' % kb.customInjectionMark), conf.data)
                    else:
                        conf.data = re.sub(r"((?P<name>'[^']+'|\w+)\s*:\s*'[^']+)'", functools.partial(process, repl=r"\g<1>%s'" % kb.customInjectionMark), conf.data)
                        conf.data = re.sub(r"((?P<name>'[^']+'|\w+)\s*:\s*)(-?\d[\d\.]*\b)", functools.partial(process, repl=r"\g<0>%s" % kb.customInjectionMark), conf.data)

        elif re.search(ARRAY_LIKE_RECOGNITION_REGEX, conf.data):
            message = "在%s主体中发现类数组数据。 " % conf.method
            message += "您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.ARRAY_LIKE
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(=[^%s]+)" % DEFAULT_GET_POST_DELIMITER, r"\g<1>%s" % kb.customInjectionMark, conf.data)

        elif re.search(XML_RECOGNITION_REGEX, conf.data):
            message = "在%s主体中发现SOAP/XML数据。 " % conf.method
            message += "您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.SOAP if "soap" in conf.data.lower() else POST_HINT.XML
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)", functools.partial(process, repl=r"\g<1>\g<4>%s\g<5>" % kb.customInjectionMark), conf.data)

        elif re.search(MULTIPART_RECOGNITION_REGEX, conf.data):
            message = "在%s主体中发现多部分数据。 " % conf.method
            message += "您想处理它吗? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.MULTIPART
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(?si)(Content-Disposition:[^\n]+\s+name=\"(?P<name>[^\"]+)\"(?:[^f|^b]|f(?!ilename=)|b(?!oundary=))*?)((%s)--)" % ("\r\n" if "\r\n" in conf.data else '\n'),
                                        functools.partial(process, repl=r"\g<1>%s\g<3>" % kb.customInjectionMark), conf.data)

        if not kb.postHint:
            if kb.customInjectionMark in conf.data:  # 后续处理
                pass
            else:
                place = PLACE.POST

                conf.parameters[place] = conf.data
                paramDict = paramToDict(place, conf.data)

                if paramDict:
                    conf.paramDict[place] = paramDict
                    testableParameters = True
        else:
            if kb.customInjectionMark not in conf.data:  # 如果没有找到可用的参数值
                conf.parameters[PLACE.POST] = conf.data

    kb.processUserMarks = True if (kb.postHint and kb.customInjectionMark in (conf.data or "")) else kb.processUserMarks

    if re.search(URI_INJECTABLE_REGEX, conf.url, re.I) and not any(place in conf.parameters for place in (PLACE.GET, PLACE.POST)) and not kb.postHint and kb.customInjectionMark not in (conf.data or "") and conf.url.startswith("http"):
        warnMsg = "您提供的目标URL没有任何GET "
        warnMsg += "参数 (例如 'http://www.site.com/article.php?id=1') "
        warnMsg += "并且没有通过 '--data' 提供任何POST参数"
        logger.warning(warnMsg)

        message = "您想尝试URI注入 "
        message += "在目标URL本身吗? [Y/n/q] "
        choice = readInput(message, default='Y').upper()

        if choice == 'Q':
            raise SqlmapUserQuitException
        elif choice == 'Y':
            conf.url = "%s%s" % (conf.url, kb.customInjectionMark)
            kb.processUserMarks = True

    for place, value in ((PLACE.URI, conf.url), (PLACE.CUSTOM_POST, conf.data), (PLACE.CUSTOM_HEADER, str(conf.httpHeaders))):
        if place == PLACE.CUSTOM_HEADER and any((conf.forms, conf.crawlDepth)):
            continue

        _ = re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or "") if place == PLACE.CUSTOM_HEADER else value or ""
        if kb.customInjectionMark in _:
            if kb.processUserMarks is None:
                lut = {PLACE.URI: '-u', PLACE.CUSTOM_POST: '--data', PLACE.CUSTOM_HEADER: '--headers/--user-agent/--referer/--cookie'}
                message = "在选项中发现自定义注入标记 ('%s') " % kb.customInjectionMark
                message += "'%s'。您想处理它吗? [Y/n/q] " % lut[place]
                choice = readInput(message, default='Y').upper()

                if choice == 'Q':
                    raise SqlmapUserQuitException
                else:
                    kb.processUserMarks = choice == 'Y'

                    if kb.processUserMarks:
                        kb.testOnlyCustom = True

                        if "=%s" % kb.customInjectionMark in _:
                            warnMsg = "看起来您提供了空参数值 "
                            warnMsg += "用于测试。请始终仅使用有效的参数值 "
                            warnMsg += "以便sqlmap能够正常运行"
                            logger.warning(warnMsg)

            if not kb.processUserMarks:
                if place == PLACE.URI:
                    query = _urllib.parse.urlsplit(value).query
                    if query:
                        parameters = conf.parameters[PLACE.GET] = query
                        paramDict = paramToDict(PLACE.GET, parameters)

                        if paramDict:
                            conf.url = conf.url.split('?')[0]
                            conf.paramDict[PLACE.GET] = paramDict
                            testableParameters = True
                elif place == PLACE.CUSTOM_POST:
                    conf.parameters[PLACE.POST] = conf.data
                    paramDict = paramToDict(PLACE.POST, conf.data)

                    if paramDict:
                        conf.paramDict[PLACE.POST] = paramDict
                        testableParameters = True

            else:
                if place == PLACE.URI:
                    value = conf.url = conf.url.replace('+', "%20")  # 注意: https://github.com/sqlmapproject/sqlmap/issues/5123

                conf.parameters[place] = value
                conf.paramDict[place] = OrderedDict()

                if place == PLACE.CUSTOM_HEADER:
                    for index in xrange(len(conf.httpHeaders)):
                        header, value = conf.httpHeaders[index]
                        if kb.customInjectionMark in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value):
                            parts = value.split(kb.customInjectionMark)
                            for i in xrange(len(parts) - 1):
                                conf.paramDict[place]["%s #%d%s" % (header, i + 1, kb.customInjectionMark)] = "%s,%s" % (header, "".join("%s%s" % (parts[j], kb.customInjectionMark if i == j else "") for j in xrange(len(parts))))
                            conf.httpHeaders[index] = (header, value.replace(kb.customInjectionMark, ""))
                else:
                    parts = value.split(kb.customInjectionMark)

                    for i in xrange(len(parts) - 1):
                        name = None
                        if kb.postHint:
                            for ending, _ in hintNames:
                                if parts[i].endswith(ending):
                                    name = "%s %s" % (kb.postHint, _)
                                    break
                        if name is None:
                            name = "%s#%s%s" % (("%s " % kb.postHint) if kb.postHint else "", i + 1, kb.customInjectionMark)
                        conf.paramDict[place][name] = "".join("%s%s" % (parts[j], kb.customInjectionMark if i == j else "") for j in xrange(len(parts)))

                    if place == PLACE.URI and PLACE.GET in conf.paramDict:
                        del conf.paramDict[PLACE.GET]
                    elif place == PLACE.CUSTOM_POST and PLACE.POST in conf.paramDict:
                        del conf.paramDict[PLACE.POST]

                testableParameters = True

    if kb.processUserMarks:
        for item in ("url", "data", "agent", "referer", "cookie"):
            if conf.get(item):
                conf[item] = conf[item].replace(kb.customInjectionMark, "")

    # 对Cookie参数执行检查
    if conf.cookie:
        conf.parameters[PLACE.COOKIE] = conf.cookie
        paramDict = paramToDict(PLACE.COOKIE, conf.cookie)

        if paramDict:
            conf.paramDict[PLACE.COOKIE] = paramDict
            testableParameters = True

    # 对header值执行检查
    if conf.httpHeaders:
        for httpHeader, headerValue in list(conf.httpHeaders):
            # 应避免对header值进行URL编码
            # 参考: http://stackoverflow.com/questions/5085904/is-ok-to-urlencode-the-value-in-headerlocation-value

            if httpHeader.upper() == HTTP_HEADER.USER_AGENT.upper():
                conf.parameters[PLACE.USER_AGENT] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, USER_AGENT_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.USER_AGENT] = {PLACE.USER_AGENT: headerValue}
                    testableParameters = True

            elif httpHeader.upper() == HTTP_HEADER.REFERER.upper():
                conf.parameters[PLACE.REFERER] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, REFERER_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.REFERER] = {PLACE.REFERER: headerValue}
                    testableParameters = True

            elif httpHeader.upper() == HTTP_HEADER.HOST.upper():
                conf.parameters[PLACE.HOST] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, HOST_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.HOST] = {PLACE.HOST: headerValue}
                    testableParameters = True

            else:
                condition = intersect(conf.testParameter, [httpHeader], True)

                if condition:
                    conf.parameters[PLACE.CUSTOM_HEADER] = str(conf.httpHeaders)
                    conf.paramDict[PLACE.CUSTOM_HEADER] = {httpHeader: "%s,%s%s" % (httpHeader, headerValue, kb.customInjectionMark)}
                    conf.httpHeaders = [(_[0], _[1].replace(kb.customInjectionMark, "")) for _ in conf.httpHeaders]
                    testableParameters = True

    if not conf.parameters:
        errMsg = "您没有提供任何GET、POST和Cookie "
        errMsg += "参数，也没有提供User-Agent、Referer或Host头值"
        raise SqlmapGenericException(errMsg)

    elif not testableParameters:
        errMsg = "您提供的所有可测参数在给定的请求数据中不存在"
        raise SqlmapGenericException(errMsg)

    if conf.csrfToken:
        if not any(re.search(conf.csrfToken, ' '.join(_), re.I) for _ in (conf.paramDict.get(PLACE.GET, {}), conf.paramDict.get(PLACE.POST, {}), conf.paramDict.get(PLACE.COOKIE, {}))) and not re.search(r"\b%s\b" % conf.csrfToken, conf.data or "") and conf.csrfToken not in set(_[0].lower() for _ in conf.httpHeaders) and conf.csrfToken not in conf.paramDict.get(PLACE.COOKIE, {}) and not all(re.search(conf.csrfToken, _, re.I) for _ in conf.paramDict.get(PLACE.URI, {}).values()):
            errMsg = "在提供的GET、POST、Cookie或header值中未找到反CSRF令牌参数 '%s' " % conf.csrfToken._original
            raise SqlmapGenericException(errMsg)
    else:
        for place in (PLACE.GET, PLACE.POST, PLACE.COOKIE):
            if conf.csrfToken:
                break

            for parameter in conf.paramDict.get(place, {}):
                if any(parameter.lower().count(_) for _ in CSRF_TOKEN_PARAMETER_INFIXES):
                    message = "%s参数 '%s' 似乎包含反CSRF令牌。 " % ("%s " % place if place != parameter else "", parameter)
                    message += "您希望sqlmap在后续请求中自动更新它吗? [y/N] "

                    if readInput(message, default='N', boolean=True):
                        class _(six.text_type):
                            pass
                        conf.csrfToken = _(re.escape(getUnicode(parameter)))
                        conf.csrfToken._original = getUnicode(parameter)
                        break

def _setHashDB():
    """
    检查并设置HashDB SQLite文件以便查询恢复功能。
    """

    if not conf.hashDBFile:
        conf.hashDBFile = conf.sessionFile or os.path.join(conf.outputPath, SESSION_SQLITE_FILE)

    if conf.flushSession:
        if os.path.exists(conf.hashDBFile):
            if conf.hashDB:
                conf.hashDB.closeAll()

            try:
                os.remove(conf.hashDBFile)
                logger.info("正在刷新会话文件")
            except OSError as ex:
                errMsg = "无法刷新会话文件 ('%s')" % getSafeExString(ex)
                raise SqlmapFilePathException(errMsg)

    conf.hashDB = HashDB(conf.hashDBFile)

def _resumeHashDBValues():
    """
    恢复来自HashDB的存储数据值
    """

    kb.absFilePaths = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True) or kb.absFilePaths
    kb.brute.tables = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_TABLES, True) or kb.brute.tables
    kb.brute.columns = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_COLUMNS, True) or kb.brute.columns
    kb.chars = hashDBRetrieve(HASHDB_KEYS.KB_CHARS, True) or kb.chars
    kb.dynamicMarkings = hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, True) or kb.dynamicMarkings
    kb.xpCmdshellAvailable = hashDBRetrieve(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE) or kb.xpCmdshellAvailable

    kb.errorChunkLength = hashDBRetrieve(HASHDB_KEYS.KB_ERROR_CHUNK_LENGTH)
    if isNumPosStrValue(kb.errorChunkLength):
        kb.errorChunkLength = int(kb.errorChunkLength)
    else:
        kb.errorChunkLength = None

    conf.tmpPath = conf.tmpPath or hashDBRetrieve(HASHDB_KEYS.CONF_TMP_PATH)

    for injection in hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True) or []:
        if isinstance(injection, InjectionDict) and injection.place in conf.paramDict and injection.parameter in conf.paramDict[injection.place]:
            if not conf.technique or intersect(conf.technique, injection.data.keys()):
                if intersect(conf.technique, injection.data.keys()):
                    injection.data = dict(_ for _ in injection.data.items() if _[0] in conf.technique)
                if injection not in kb.injections:
                    kb.injections.append(injection)
                    kb.vulnHosts.add(conf.hostname)

    _resumeDBMS()
    _resumeOS()

def _resumeDBMS():
    """
    恢复来自HashDB存储的DBMS信息
    """

    value = hashDBRetrieve(HASHDB_KEYS.DBMS)

    if not value:
        if conf.offline:
            errMsg = "无法在离线模式下继续 "
            errMsg += "因为缺乏可用的 "
            errMsg += "会话数据"
            raise SqlmapNoneDataException(errMsg)
        else:
            return

    dbms = value.lower()
    dbmsVersion = [UNKNOWN_DBMS_VERSION]
    _ = "(%s)" % ('|'.join(SUPPORTED_DBMS))
    _ = re.search(r"\A%s (.*)" % _, dbms, re.I)

    if _:
        dbms = _.group(1).lower()
        dbmsVersion = [_.group(2)]

    if conf.dbms:
        check = True
        for aliases, _, _, _ in DBMS_DICT.values():
            if conf.dbms.lower() in aliases and dbms not in aliases:
                check = False
                break

        if not check:
            message = "您提供了 '%s' 作为后端DBMS，" % conf.dbms
            message += "但根据对目标URL的先前扫描信息，"
            message += "sqlmap假定后端DBMS为 '%s'。" % dbms
            message += "您真的想强制设置后端DBMS值吗? [y/N] "

            if not readInput(message, default='N', boolean=True):
                conf.dbms = None
                Backend.setDbms(dbms)
                Backend.setVersionList(dbmsVersion)
    else:
        infoMsg = "正在恢复后端DBMS '%s' " % dbms
        logger.info(infoMsg)

        Backend.setDbms(dbms)
        Backend.setVersionList(dbmsVersion)

def _resumeOS():
    """
    恢复来自HashDB存储的OS信息
    """

    value = hashDBRetrieve(HASHDB_KEYS.OS)

    if not value:
        return

    os = value

    if os and os != 'None':
        infoMsg = "正在恢复后端DBMS操作系统 '%s' " % os
        logger.info(infoMsg)

        if conf.os and conf.os.lower() != os.lower():
            message = "您提供了 '%s' 作为后端DBMS操作系统，但从以往扫描信息中，" % conf.os
            message += "sqlmap假定后端DBMS操作系统为 %s。" % os
            message += "您真的想强制设置后端DBMS操作系统值吗? [y/N] "

            if not readInput(message, default='N', boolean=True):
                conf.os = os
        else:
            conf.os = os

        Backend.setOs(conf.os)

def _setResultsFile():
    """
    创建结果文件用于存储在多目标模式下运行的结果。
    """

    if not conf.multipleTargets:
        return

    if not conf.resultsFP:
        conf.resultsFile = conf.resultsFile or os.path.join(paths.SQLMAP_OUTPUT_PATH, time.strftime(RESULTS_FILE_FORMAT).lower())
        found = os.path.exists(conf.resultsFile)

        try:
            conf.resultsFP = openFile(conf.resultsFile, "a", UNICODE_ENCODING, buffering=0)
        except (OSError, IOError) as ex:
            try:
                warnMsg = "无法创建结果文件 '%s' ('%s')。" % (conf.resultsFile, getUnicode(ex))
                handle, conf.resultsFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.RESULTS, suffix=".csv")
                os.close(handle)
                conf.resultsFP = openFile(conf.resultsFile, "w+", UNICODE_ENCODING, buffering=0)
                warnMsg += "使用临时文件 '%s' 替代" % conf.resultsFile
                logger.warning(warnMsg)
            except IOError as _:
                errMsg = "无法写入临时目录 ('%s')。" % _
                errMsg += "请确保您的磁盘没有满，并且您有足够的写权限 "
                errMsg += "以创建临时文件和/或目录"
                raise SqlmapSystemException(errMsg)

        if not found:
            conf.resultsFP.writelines("目标URL,位置,参数,技术(们),备注(们)%s" % os.linesep)

        logger.info("在多目标模式中使用 '%s' 作为CSV结果文件" % conf.resultsFile)

def _createFilesDir():
    """
    创建文件目录。
    """

    if not any((conf.fileRead, conf.commonFiles)):
        return

    conf.filePath = paths.SQLMAP_FILES_PATH % conf.hostname

    if not os.path.isdir(conf.filePath):
        try:
            os.makedirs(conf.filePath)
        except OSError as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmapfiles")
            warnMsg = "无法创建文件目录 "
            warnMsg += "'%s' (%s)。" % (conf.filePath, getUnicode(ex))
            warnMsg += "使用临时目录 '%s' 替代" % getUnicode(tempDir)
            logger.warning(warnMsg)

            conf.filePath = tempDir

def _createDumpDir():
    """
    创建转储目录。
    """

    if not conf.dumpTable and not conf.dumpAll and not conf.search:
        return

    conf.dumpPath = safeStringFormat(paths.SQLMAP_DUMP_PATH, conf.hostname)

    if not os.path.isdir(conf.dumpPath):
        try:
            os.makedirs(conf.dumpPath)
        except Exception as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmapdump")
            warnMsg = "无法创建转储目录 "
            warnMsg += "'%s' (%s)。" % (conf.dumpPath, getUnicode(ex))
            warnMsg += "使用临时目录 '%s' 替代" % getUnicode(tempDir)
            logger.warning(warnMsg)

            conf.dumpPath = tempDir

def _configureDumper():
    conf.dumper = dumper
    conf.dumper.setOutputFile()

def _createTargetDirs():
    """
    创建输出目录。
    """

    conf.outputPath = os.path.join(getUnicode(paths.SQLMAP_OUTPUT_PATH), normalizeUnicode(getUnicode(conf.hostname)))

    try:
        if not os.path.isdir(conf.outputPath):
            os.makedirs(conf.outputPath)
    except (OSError, IOError, TypeError) as ex:
        tempDir = tempfile.mkdtemp(prefix="sqlmapoutput")
        warnMsg = "无法创建输出目录 "
        warnMsg += "'%s' (%s)。" % (conf.outputPath, getUnicode(ex))
        warnMsg += "使用临时目录 '%s' 替代" % getUnicode(tempDir)
        logger.warning(warnMsg)

        conf.outputPath = tempDir

    conf.outputPath = getUnicode(conf.outputPath)

    try:
        with openFile(os.path.join(conf.outputPath, "target.txt"), "w+") as f:
            f.write(getUnicode(kb.originalUrls.get(conf.url) or conf.url or conf.hostname))
            f.write(" (%s)" % (HTTPMETHOD.POST if conf.data else HTTPMETHOD.GET))
            f.write("  # %s" % getUnicode(subprocess.list2cmdline(sys.argv), encoding=sys.stdin.encoding))
            if conf.data:
                f.write("\n\n%s" % getUnicode(conf.data))
    except IOError as ex:
        if "denied" in getUnicode(ex):
            errMsg = "您没有足够的权限 "
        else:
            errMsg = "在尝试时发生了错误 "
        errMsg += "写入输出目录 '%s' (%s)" % (paths.SQLMAP_OUTPUT_PATH, getSafeExString(ex))

        raise SqlmapMissingPrivileges(errMsg)
    except UnicodeError as ex:
        warnMsg = "保存目标数据时发生了错误 ('%s')" % getSafeExString(ex)
        logger.warning(warnMsg)

    _createDumpDir()
    _createFilesDir()
    _configureDumper()

def _setAuxOptions():
    """
    设置辅助（依赖于主机的）选项
    """

    kb.aliasName = randomStr(seed=hash(conf.hostname or ""))

def _restoreMergedOptions():
    """
    恢复合并选项（命令行、配置文件和默认值）
    这些选项在测试之前可能已被更改。
    """

    for option in RESTORE_MERGED_OPTIONS:
        conf[option] = mergedOptions[option]

def initTargetEnv():
    """
    初始化目标环境。
    """

    if conf.multipleTargets:
        if conf.hashDB:
            conf.hashDB.close()

        if conf.cj:
            resetCookieJar(conf.cj)

        threadData = getCurrentThreadData()
        threadData.reset()

        conf.paramDict = {}
        conf.parameters = {}
        conf.hashDBFile = None

        _setKnowledgeBaseAttributes(False)
        _restoreMergedOptions()
        _setDBMS()

    if conf.data:
        class _(six.text_type):
            pass

        kb.postUrlEncode = True

        for key, value in conf.httpHeaders:
            if key.upper() == HTTP_HEADER.CONTENT_TYPE.upper():
                kb.postUrlEncode = "urlencoded" in value
                break

        if kb.postUrlEncode:
            original = conf.data
            conf.data = _(urldecode(conf.data))
            setattr(conf.data, UNENCODED_ORIGINAL_VALUE, original)
            kb.postSpaceToPlus = '+' in original

    if conf.data and unArrayizeValue(conf.base64Parameter) == HTTPMETHOD.POST:
        if '=' not in conf.data.strip('='):
            try:
                original = conf.data
                conf.data = _(decodeBase64(conf.data, binary=False))
                setattr(conf.data, UNENCODED_ORIGINAL_VALUE, original)
            except:
                pass

    match = re.search(INJECT_HERE_REGEX, "%s %s %s" % (conf.url, conf.data, conf.httpHeaders))
    kb.customInjectionMark = match.group(0) if match else CUSTOM_INJECTION_MARK_CHAR

def setupTargetEnv():
    _createTargetDirs()  # 创建目标目录
    _setRequestParams()  # 设置请求参数
    _setHashDB()  # 设置HashDB
    _resumeHashDBValues()  # 恢复HashDB值
    _setResultsFile()  # 设置结果文件
    _setAuthCred()  # 设置认证凭据
    _setAuxOptions()  # 设置辅助选项
