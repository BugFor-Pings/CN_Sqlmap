#!/usr/bin/env python

"""
版权 (c) 2006-2024 sqlmap 开发者 (https://sqlmap.org/)
请参阅文件 'LICENSE' 以获取复制权限
"""

import copy
import logging
import random
import re
import socket
import time

from extra.beep.beep import beep
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import extractTextTagContent
from lib.core.common import filterNone
from lib.core.common import findDynamicContent
from lib.core.common import Format
from lib.core.common import getFilteredPageContent
from lib.core.common import getLastRequestHTTPError
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import getSortedInjectionTests
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import isDigit
from lib.core.common import joinValue
from lib.core.common import listToStrValue
from lib.core.common import parseFilePaths
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import showStaticWords
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import wasLastResponseDBMSError
from lib.core.common import wasLastResponseHTTPError
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.decorators import stackedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.dicts import HEURISTIC_NULL_EVAL
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import REDIRECTION
from lib.core.enums import WEB_PLATFORM
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import BOUNDED_INJECTION_MARKER
from lib.core.settings import CANDIDATE_SENTENCE_MIN_LENGTH
from lib.core.settings import CHECK_INTERNET_ADDRESS
from lib.core.settings import CHECK_INTERNET_VALUE
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DUMMY_NON_SQLI_CHECK_APPENDIX
from lib.core.settings import FI_ERROR_REGEX
from lib.core.settings import FORMAT_EXCEPTION_STRINGS
from lib.core.settings import HEURISTIC_CHECK_ALPHABET
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import IPS_WAF_CHECK_PAYLOAD
from lib.core.settings import IPS_WAF_CHECK_RATIO
from lib.core.settings import IPS_WAF_CHECK_TIMEOUT
from lib.core.settings import MAX_DIFFLIB_SEQUENCE_LENGTH
from lib.core.settings import MAX_STABILITY_DELAY
from lib.core.settings import NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH
from lib.core.settings import PRECONNECT_INCOMPATIBLE_SERVERS
from lib.core.settings import SINGLE_QUOTE_MARKER
from lib.core.settings import SLEEP_TIME_MARKER
from lib.core.settings import SUHOSIN_MAX_VALUE_LENGTH
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.settings import URI_HTTP_HEADER
from lib.core.threads import getCurrentThreadData
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.request.comparison import comparison
from lib.request.inject import checkBooleanExpression
from lib.request.templates import getPageTemplate
from lib.techniques.union.test import unionTest
from lib.techniques.union.use import configUnion
from thirdparty import six
from thirdparty.six.moves import http_client as _http_client

def checkSqlInjection(place, parameter, value):
    # 在这里存储有关成功注入的边界和有效负载的详细信息
    injection = InjectionDict()

    # 需要某些方法的局部线程数据
    threadData = getCurrentThreadData()

    # 偏向于非字符串特定的边界，以防参数值类似数字
    if isDigit(value):
        kb.cache.intBoundaries = kb.cache.intBoundaries or sorted(copy.deepcopy(conf.boundaries), key=lambda boundary: any(_ in (boundary.prefix or "") or _ in (boundary.suffix or "") for _ in ('"', '\'')))
        boundaries = kb.cache.intBoundaries
    elif value.isalpha():
        kb.cache.alphaBoundaries = kb.cache.alphaBoundaries or sorted(copy.deepcopy(conf.boundaries), key=lambda boundary: not any(_ in (boundary.prefix or "") or _ in (boundary.suffix or "") for _ in ('"', '\'')))
        boundaries = kb.cache.alphaBoundaries
    else:
        boundaries = conf.boundaries

    # 设置 SQL 注入测试模式标志
    kb.testMode = True

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place
    tests = getSortedInjectionTests()
    seenPayload = set()

    kb.data.setdefault("randomInt", str(randomInt(10)))
    kb.data.setdefault("randomStr", str(randomStr(10)))

    while tests:
        test = tests.pop(0)

        try:
            if kb.endDetection:
                break

            if conf.dbms is None:
                # 如果 DBMS 尚未通过简单的启发式检查或通过 DBMS 特定的有效负载指纹识别，并且已识别出基于布尔的盲注入，则尝试通过简单的 DBMS 特定的布尔测试识别可能的 DBMS
                if not injection.dbms and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
                    if not Backend.getIdentifiedDbms() and kb.heuristicDbms is None and not kb.droppingRequests:
                        kb.heuristicDbms = heuristicCheckDbms(injection)

                # 如果 DBMS 已通过 DBMS 特定的错误消息、简单的启发式检查或 DBMS 特定的有效负载指纹识别，则提示用户限制测试到指纹识别的 DBMS
                if kb.reduceTests is None and not conf.testFilter and (intersect(Backend.getErrorParsedDBMSes(), SUPPORTED_DBMS, True) or kb.heuristicDbms or injection.dbms):
                    msg = "看起来后端 DBMS 是 '%s'。 " % (Format.getErrorParsedDBMSes() or kb.heuristicDbms or joinValue(injection.dbms, '/'))
                    msg += "您想跳过其他 DBMS 特定的测试有效负载吗？ [Y/n]"
                    kb.reduceTests = (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms]) if readInput(msg, default='Y', boolean=True) else []

            # 如果 DBMS 已指纹识别（通过 DBMS 特定的错误消息、通过简单的启发式检查或通过 DBMS 特定的有效负载），则提示用户扩展测试到所有 DBMS 特定的有效负载，无论提供的 --level 和 --risk 值
            if kb.extendTests is None and not conf.testFilter and (conf.level < 5 or conf.risk < 3) and (intersect(Backend.getErrorParsedDBMSes(), SUPPORTED_DBMS, True) or kb.heuristicDbms or injection.dbms):
                msg = "对于剩余测试，您想包括所有对于 '%s' 的测试，并扩展提供的" % (Format.getErrorParsedDBMSes() or kb.heuristicDbms or joinValue(injection.dbms, '/'))
                msg += "级别 (%d)" % conf.level if conf.level < 5 else ""
                msg += " 和 " if conf.level < 5 and conf.risk < 3 else ""
                msg += "风险 (%d)" % conf.risk if conf.risk < 3 else ""
                msg += " 值吗？ [Y/n]" if conf.level < 5 and conf.risk < 3 else " 值吗？ [Y/n]"
                kb.extendTests = (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms]) if readInput(msg, default='Y', boolean=True) else []

            title = test.title
            kb.testType = stype = test.stype
            clause = test.clause
            unionExtended = False
            trueCode, falseCode = None, None

            if conf.httpCollector is not None:
                conf.httpCollector.setExtendedArguments({
                    "_title": title,
                    "_place": place,
                    "_parameter": parameter,
                })

            if stype == PAYLOAD.TECHNIQUE.UNION:
                configUnion(test.request.char)

                if "[CHAR]" in title:
                    if conf.uChar is None:
                        continue
                    else:
                        title = title.replace("[CHAR]", conf.uChar)

                elif "[RANDNUM]" in title or "(NULL)" in title:
                    title = title.replace("[RANDNUM]", "随机数字")

                if test.request.columns == "[COLSTART]-[COLSTOP]":
                    if conf.uCols is None:
                        continue
                    else:
                        title = title.replace("[COLSTART]", str(conf.uColsStart))
                        title = title.replace("[COLSTOP]", str(conf.uColsStop))

                elif conf.uCols is not None:
                    debugMsg = "跳过测试 '%s' 因为用户 " % title
                    debugMsg += "提供了自定义列范围 %s" % conf.uCols
                    logger.debug(debugMsg)
                    continue

                match = re.search(r"(\d+)-(\d+)", test.request.columns)
                if match and injection.data:
                    lower, upper = int(match.group(1)), int(match.group(2))
                    for _ in (lower, upper):
                        if _ > 1:
                            __ = 2 * (_ - 1) + 1 if _ == lower else 2 * _
                            unionExtended = True
                            test.request._columns = test.request.columns
                            test.request.columns = re.sub(r"\b%d\b" % _, str(__), test.request.columns)
                            title = re.sub(r"\b%d\b" % _, str(__), title)
                            test.title = re.sub(r"\b%d\b" % _, str(__), test.title)

            # 如果用户希望只测试特定技术，则跳过测试
            if conf.technique and isinstance(conf.technique, list) and stype not in conf.technique:
                debugMsg = "跳过测试 '%s' 因为用户 " % title
                debugMsg += "指定只测试 "
                debugMsg += "%s 技术" % " & ".join(PAYLOAD.SQLINJECTION[_] for _ in conf.technique)
                logger.debug(debugMsg)
                continue

            # 如果已经通过另一个测试识别了相同 SQL 注入类型，则跳过测试
            if injection.data and stype in injection.data:
                debugMsg = "跳过测试 '%s' 因为 " % title
                debugMsg += "针对 %s 的有效负载 %s 已经被识别" % (PAYLOAD.SQLINJECTION[stype], title)
                logger.debug(debugMsg)
                continue

            # 解析 DBMS 特定的有效负载详细信息
            if "details" in test and "dbms" in test.details:
                payloadDbms = test.details.dbms
            else:
                payloadDbms = None

            # 如果标题、向量或 DBMS 不包含在给定的测试过滤器中，则跳过测试
            if conf.testFilter and not any(conf.testFilter in str(item) or re.search(conf.testFilter, str(item), re.I) for item in (test.title, test.vector, payloadDbms)):
                debugMsg = "跳过测试 '%s' 因为其 " % title
                debugMsg += "名称/向量/DBMS 不包含在给定过滤器中"
                logger.debug(debugMsg)
                continue

            # 如果标题、向量或 DBMS 被给定的跳过过滤器包含，则跳过测试
            if conf.testSkip and any(conf.testSkip in str(item) or re.search(conf.testSkip, str(item), re.I) for item in (test.title, test.vector, payloadDbms)):
                debugMsg = "跳过测试 '%s' 因为其 " % title
                debugMsg += "名称/向量/DBMS 被给定的跳过过滤器包含"
                logger.debug(debugMsg)
                continue

            if payloadDbms is not None:
                # 如果 DBMS 特定测试与用户提供的 DBMS 不匹配，则跳过此测试
                if conf.dbms and not intersect(payloadDbms, conf.dbms, True):
                    debugMsg = "跳过测试 '%s' 因为 " % title
                    debugMsg += "其声明的 DBMS 与所提供的不同"
                    logger.debug(debugMsg)
                    continue

                elif kb.dbmsFilter and not intersect(payloadDbms, kb.dbmsFilter, True):
                    debugMsg = "跳过测试 '%s' 因为 " % title
                    debugMsg += "其声明的 DBMS 与所提供的不同"
                    logger.debug(debugMsg)
                    continue

                elif kb.reduceTests == False:
                    pass

                # 如果此 DBMS 特定测试与通过 DBMS 特定有效负载之前识别的 DBMS 不匹配，则跳过此测试
                elif injection.dbms and not intersect(payloadDbms, injection.dbms, True):
                    debugMsg = "跳过测试 '%s' 因为 " % title
                    debugMsg += "其声明的 DBMS 与已识别的不同"
                    logger.debug(debugMsg)
                    continue

                # 如果此 DBMS 特定测试与通过 DBMS 特定错误消息之前识别的 DBMS 不匹配，则跳过此测试
                elif kb.reduceTests and not intersect(payloadDbms, kb.reduceTests, True):
                    debugMsg = "跳过测试 '%s' 因为启发式 " % title
                    debugMsg += "测试显示后端 DBMS 可能是 '%s'" % unArrayizeValue(kb.reduceTests)
                    logger.debug(debugMsg)
                    continue

            # 如果用户未决定扩展测试到所有 DBMS 特定有效负载，或测试有效负载与已识别的 DBMS 不特定，则仅在等级和风险都低于相应配置的等级和风险值时才进行测试
            if not conf.testFilter and not (kb.extendTests and intersect(payloadDbms, kb.extendTests, True)):
                # 如果风险高于提供的（或默认）值，则跳过测试
                if test.risk > conf.risk:
                    debugMsg = "跳过测试 '%s' 因为风险 (%d) " % (title, test.risk)
                    debugMsg += "高于提供的 (%d)" % conf.risk
                    logger.debug(debugMsg)
                    continue

                # 如果等级高于提供的（或默认）值，则跳过测试
                if test.level > conf.level:
                    debugMsg = "跳过测试 '%s' 因为等级 (%d) " % (title, test.level)
                    debugMsg += "高于提供的 (%d)" % conf.level
                    logger.debug(debugMsg)
                    continue

            # 如果与另一个测试已经识别的 SQL 注入子句不匹配，则跳过测试
            clauseMatch = False

            for clauseTest in clause:
                if injection.clause is not None and clauseTest in injection.clause:
                    clauseMatch = True
                    break

            if clause != [0] and injection.clause and injection.clause != [0] and not clauseMatch:
                debugMsg = "跳过测试 '%s' 因为子句 " % title
                debugMsg += "与已识别的子句不同"
                logger.debug(debugMsg)
                continue

            # 如果用户提供了自定义字符（用于基于 UNION 的有效负载），则跳过测试
            if conf.uChar is not None and ("随机数字" in title or "(NULL)" in title):
                debugMsg = "跳过测试 '%s' 因为用户 " % title
                debugMsg += "提供了特定字符 %s" % conf.uChar
                logger.debug(debugMsg)
                continue

            if stype == PAYLOAD.TECHNIQUE.UNION:
                match = re.search(r"(\d+)-(\d+)", test.request.columns)
                if match and not injection.data:
                    _ = test.request.columns.split('-')[-1]
                    if conf.uCols is None and _.isdigit():
                        if kb.futileUnion is None:
                            msg = "建议在没有其他（潜在）技术发现的情况下，仅执行基础的 UNION 测试。您想减少请求的数量吗？ [Y/n] "
                            kb.futileUnion = readInput(msg, default='Y', boolean=True)

                        if kb.futileUnion and int(_) > 10:
                            debugMsg = "跳过测试 '%s'" % title
                            logger.debug(debugMsg)
                            continue

            infoMsg = "测试 '%s'" % title
            logger.info(infoMsg)

            # 根据当前测试 DBMS 值强制后端 DBMS，以便正确的有效负载取消转义
            Backend.forceDbms(payloadDbms[0] if isinstance(payloadDbms, list) else payloadDbms)

            # 解析测试的 <request>
            comment = agent.getComment(test.request) if len(conf.boundaries) > 1 else None
            fstPayload = agent.cleanupPayload(test.request.payload, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) and BOUNDED_INJECTION_MARKER not in (value or "") else None)

            for boundary in boundaries:
                injectable = False

                # 如果级别高于提供的（或默认的）值，则跳过边界
                # 解析边界的 <level>
                if boundary.level > conf.level and not (kb.extendTests and intersect(payloadDbms, kb.extendTests, True)):
                    continue

                # 如果与测试的 <clause> 不匹配，则跳过边界
                # 解析测试的 <clause> 和边界的 <clause>
                clauseMatch = False

                for clauseTest in test.clause:
                    if clauseTest in boundary.clause:
                        clauseMatch = True
                        break

                if test.clause != [0] and boundary.clause != [0] and not clauseMatch:
                    continue

                # 如果与测试的 <where> 不匹配，则跳过边界
                # 解析测试的 <where> 和边界的 <where>
                whereMatch = False

                for where in test.where:
                    if where in boundary.where:
                        whereMatch = True
                        break

                if not whereMatch:
                    continue

                # 解析边界的 <prefix>、<suffix> 和 <ptype>
                prefix = boundary.prefix or ""
                suffix = boundary.suffix or ""
                ptype = boundary.ptype

                # 选项 --prefix/--suffix 优先级更高（如果由用户设置）
                prefix = conf.prefix if conf.prefix is not None else prefix
                suffix = conf.suffix if conf.suffix is not None else suffix
                comment = None if conf.suffix is not None else comment

                # 如果之前的注入成功，我们知道在后续测试中要使用哪个前缀、后缀和参数类型，后续测试不需要遍历边界
                condBound = (injection.prefix is not None and injection.suffix is not None)
                condBound &= (injection.prefix != prefix or injection.suffix != suffix)
                condType = injection.ptype is not None and injection.ptype != ptype

                # 如果有效负载是行内查询，请无论如何对其进行测试，尽管之前已识别的注入类型
                if stype != PAYLOAD.TECHNIQUE.QUERY and (condBound or condType):
                    continue

                # 针对每个测试的 <where>
                for where in test.where:
                    templatePayload = None
                    vector = None

                    origValue = value
                    if kb.customInjectionMark in origValue:
                        origValue = origValue.split(kb.customInjectionMark)[0]
                        origValue = re.search(r"(\w*)\Z", origValue).group(1)

                    # 根据测试的 <where> 标记来处理参数的原始值
                    if where == PAYLOAD.WHERE.ORIGINAL or conf.prefix:
                        if kb.tamperFunctions:
                            templatePayload = agent.payload(place, parameter, value="", newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.NEGATIVE:
                        # 使用与原始页面模板不同的页面模板，因为我们正在更改参数值，这可能会导致不同的内容
                        if conf.invalidLogical:
                            _ = int(kb.data.randomInt[:2])
                            origValue = "%s AND %s LIKE %s" % (origValue, _, _ + 1)
                        elif conf.invalidBignum:
                            origValue = kb.data.randomInt[:6]
                        elif conf.invalidString:
                            origValue = kb.data.randomStr[:6]
                        else:
                            origValue = "-%s" % kb.data.randomInt[:4]

                        templatePayload = agent.payload(place, parameter, value="", newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.REPLACE:
                        origValue = ""

                    kb.pageTemplate, kb.errorIsNone = getPageTemplate(templatePayload, place)

                    # 通过在测试的 '<payload><comment>' 字符串中添加边界的前缀和后缀来伪造请求有效负载
                    if fstPayload:
                        boundPayload = agent.prefixQuery(fstPayload, prefix, where, clause)
                        boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                        reqPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                        if reqPayload:
                            stripPayload = re.sub(r"(\A|\b|_)([A-Za-z]{4}((?<!LIKE))|\d+)(_|\b|\Z)", r"\g<1>.\g<4>", reqPayload)
                            if stripPayload in seenPayload:
                                continue
                            else:
                                seenPayload.add(stripPayload)
                    else:
                        reqPayload = None

                    # 执行测试请求并检查有效负载是否成功
                    # 解析测试的 <response>
                    for method, check in test.response.items():
                        check = agent.cleanupPayload(check, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) and BOUNDED_INJECTION_MARKER not in (value or "") else None)

                        # 在基于布尔的盲 SQL 注入的情况下
                        if method == PAYLOAD.METHOD.COMPARISON:
                            # 生成用于比较的有效负载
                            def genCmpPayload():
                                sndPayload = agent.cleanupPayload(test.response.comparison, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) and BOUNDED_INJECTION_MARKER not in (value or "") else None)

                                # 通过在测试的 '<payload><comment>' 字符串中添加边界的前缀和后缀来伪造响应有效负载
                                boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                                boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                cmpPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                return cmpPayload

                            # 有助于在基于 False 的响应内容中首先设置 kb.matchRatio
                            kb.matchRatio = None
                            kb.negativeLogic = (where == PAYLOAD.WHERE.NEGATIVE)
                            suggestion = None
                            Request.queryPage(genCmpPayload(), place, raise404=False)
                            falsePage, falseHeaders, falseCode = threadData.lastComparisonPage or "", threadData.lastComparisonHeaders, threadData.lastComparisonCode
                            falseRawResponse = "%s%s" % (falseHeaders, falsePage)

                            # 检查当前 FALSE、原始和启发式页面之间是否存在差异（即未使用的参数）
                            if not any((kb.negativeLogic, conf.string, conf.notString, conf.code)):
                                try:
                                    ratio = 1.0
                                    seqMatcher = getCurrentThreadData().seqMatcher

                                    for current in (kb.originalPage, kb.heuristicPage):
                                        seqMatcher.set_seq1(current or "")
                                        seqMatcher.set_seq2(falsePage or "")
                                        ratio *= seqMatcher.quick_ratio()

                                    if ratio == 1.0:
                                        continue
                                except (MemoryError, OverflowError):
                                    pass

                            # 执行测试的正确请求
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)
                            truePage, trueHeaders, trueCode = threadData.lastComparisonPage or "", threadData.lastComparisonHeaders, threadData.lastComparisonCode
                            trueRawResponse = "%s%s" % (trueHeaders, truePage)

                            if trueResult and not (truePage == falsePage and not any((kb.nullConnection, conf.code))):
                                # 执行测试的错误请求
                                falseResult = Request.queryPage(genCmpPayload(), place, raise404=False)

                                if not falseResult:
                                    if kb.negativeLogic:
                                        boundPayload = agent.prefixQuery(kb.data.randomStr, prefix, where, clause)
                                        boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                        errorPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                        errorResult = Request.queryPage(errorPayload, place, raise404=False)
                                        if errorResult:
                                            continue
                                    elif kb.heuristicPage and not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                        _ = comparison(kb.heuristicPage, None, getRatioValue=True)
                                        if (_ or 0) > (kb.matchRatio or 0):
                                            kb.matchRatio = _
                                            logger.debug("根据当前参数调整匹配比例到 %.3f" % kb.matchRatio)

                                    # 在重度动态环境中减少虚假消息 "出现" 的情况
                                    if kb.heavilyDynamic and not Request.queryPage(reqPayload, place, raise404=False):
                                        continue

                                    injectable = True

                                elif (threadData.lastComparisonRatio or 0) > UPPER_RATIO_BOUND and not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                    originalSet = set(getFilteredPageContent(kb.pageTemplate, True, "\n").split("\n"))
                                    trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
                                    falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))

                                    if threadData.lastErrorPage and threadData.lastErrorPage[1]:
                                        errorSet = set(getFilteredPageContent(threadData.lastErrorPage[1], True, "\n").split("\n"))
                                    else:
                                        errorSet = set()

                                    if originalSet == trueSet != falseSet:
                                        candidates = trueSet - falseSet - errorSet

                                        if candidates:
                                            candidates = sorted(candidates, key=len)
                                            for candidate in candidates:
                                                if re.match(r"\A[\w.,! ]+\Z", candidate) and ' ' in candidate and candidate.strip() and len(candidate) > CANDIDATE_SENTENCE_MIN_LENGTH:
                                                    suggestion = conf.string = candidate
                                                    injectable = True

                                                    infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 (使用 --string=\"%s\")" % ("%s " % paramType if paramType != parameter else "", parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                                    logger.info(infoMsg)

                                                    break

                            if injectable:
                                if kb.pageStable and not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                    if all((falseCode, trueCode)) and falseCode != trueCode and trueCode != kb.heuristicCode:
                                        suggestion = conf.code = trueCode

                                        infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 (使用 --code=%d)" % ("%s " % paramType if paramType != parameter else "", parameter, title, conf.code)
                                        logger.info(infoMsg)
                                    else:
                                        trueSet = set(extractTextTagContent(trueRawResponse))
                                        trueSet |= set(__ for _ in trueSet for __ in _.split())

                                        falseSet = set(extractTextTagContent(falseRawResponse))
                                        falseSet |= set(__ for _ in falseSet for __ in _.split())

                                        if threadData.lastErrorPage and threadData.lastErrorPage[1]:
                                            errorSet = set(extractTextTagContent(threadData.lastErrorPage[1]))
                                            errorSet |= set(__ for _ in errorSet for __ in _.split())
                                        else:
                                            errorSet = set()

                                        candidates = filterNone(_.strip() if _.strip() in trueRawResponse and _.strip() not in falseRawResponse else None for _ in (trueSet - falseSet - errorSet))

                                        if candidates:
                                            candidates = sorted(candidates, key=len)
                                            for candidate in candidates:
                                                if re.match(r"\A\w{2,}\Z", candidate):  # 注意：长度为 1（例如 --string=5）可能会在部分反映有效负载内容的错误消息页面中造成问题
                                                    break

                                            suggestion = conf.string = candidate

                                            infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 (使用 --string=\"%s\")" % ("%s " % paramType if paramType != parameter else "", parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                            logger.info(infoMsg)

                                        if not any((conf.string, conf.notString)):
                                            candidates = filterNone(_.strip() if _.strip() in falseRawResponse and _.strip() not in trueRawResponse else None for _ in (falseSet - trueSet))

                                            if candidates:
                                                candidates = sorted(candidates, key=len)
                                                for candidate in candidates:
                                                    if re.match(r"\A\w+\Z", candidate):
                                                        break

                                                suggestion = conf.notString = candidate

                                                infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 (使用 --not-string=\"%s\")" % ("%s " % paramType if paramType != parameter else "", parameter, title, repr(conf.notString).lstrip('u').strip("'"))
                                                logger.info(infoMsg)

                                if not suggestion:
                                    infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 " % ("%s " % paramType if paramType != parameter else "", parameter, title)
                                    singleTimeLogMessage(infoMsg)

                        # 在基于错误的 SQL 注入的情况下
                        elif method == PAYLOAD.METHOD.GREP:
                            # 执行测试请求并在测试的 <grep> 正则表达式内提取响应体
                            try:
                                page, headers, _ = Request.queryPage(reqPayload, place, content=True, raise404=False)
                                output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE)
                                output = output or extractRegexResult(check, threadData.lastHTTPError[2] if wasLastResponseHTTPError() else None, re.DOTALL | re.IGNORECASE)
                                output = output or extractRegexResult(check, listToStrValue((headers[key] for key in headers if key.lower() != URI_HTTP_HEADER.lower()) if headers else None), re.DOTALL | re.IGNORECASE)
                                output = output or extractRegexResult(check, threadData.lastRedirectMsg[1] if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

                                if output:
                                    result = output == '1'

                                    if result:
                                        infoMsg = "%s参数 '%s' 是 '%s' 可注入的 " % ("%s " % paramType if paramType != parameter else "", parameter, title)
                                        logger.info(infoMsg)

                                        injectable = True

                            except SqlmapConnectionException as ex:
                                debugMsg = "出现的问题，很可能是因为服务器未能按预期从使用的基于错误的有效负载恢复 ('%s')" % getSafeExString(ex)
                                logger.debug(debugMsg)

                        # 在基于时间的盲注或堆叠查询的 SQL 注入的情况下
                        elif method == PAYLOAD.METHOD.TIME:
                            # 执行测试请求
                            trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)
                            trueCode = threadData.lastCode

                            if trueResult:
                                # 额外验证步骤（例如检查 DROP 保护机制）
                                if SLEEP_TIME_MARKER in reqPayload:
                                    falseResult = Request.queryPage(reqPayload.replace(SLEEP_TIME_MARKER, "0"), place, timeBasedCompare=True, raise404=False)
                                    if falseResult:
                                        continue

                                # 确认测试结果
                                trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                                if trueResult:
                                    infoMsg = "%s参数 '%s' 看起来是 '%s' 可注入的 " % ("%s " % paramType if paramType != parameter else "", parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # 在基于 UNION 查询的 SQL 注入的情况下
                        elif method == PAYLOAD.METHOD.UNION:
                            # 测试 UNION 注入并设置样本
                            # 有效载荷以及向量。
                            # 注意：向量设置为包含 6 个元素的元组，
                            # 之后由 Agent.forgeUnionQuery() 方法伪造 UNION 查询有效负载
                            configUnion(test.request.char, test.request.columns)

                            if len(kb.dbmsFilter or []) == 1:
                                Backend.forceDbms(kb.dbmsFilter[0])
                            elif not Backend.getIdentifiedDbms():
                                if kb.heuristicDbms is None:
                                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE or injection.data:
                                        warnMsg = "由于对后端 DBMS 的零知识，使用未转义的测试版本"
                                        warnMsg += "您可以尝试通过选项 '--dbms' 明确设置"
                                        singleTimeWarnMessage(warnMsg)
                                else:
                                    Backend.forceDbms(kb.heuristicDbms)

                            if unionExtended:
                                infoMsg = "自动扩展 UNION "
                                infoMsg += "查询注入技术测试的范围，因为 "
                                infoMsg += "发现至少另一个（潜在的）技术"
                                singleTimeLogMessage(infoMsg)

                            # 测试 UNION 查询 SQL 注入
                            reqPayload, vector = unionTest(comment, place, parameter, value, prefix, suffix)

                            if isinstance(reqPayload, six.string_types):
                                infoMsg = "%s参数 '%s' 是 '%s' 可注入的" % ("%s " % paramType if paramType != parameter else "", parameter, title)
                                logger.info(infoMsg)

                                injectable = True

                                # 重写 'where' 因为它可以直接由 unionTest() 设置
                                where = vector[6]

                        kb.previousMethod = method

                        if conf.offline:
                            injectable = False

                    # 如果注入测试成功，则将测试的详细信息提供给注入对象
                    if injectable is True:
                        # 仅在有效负载成功第一次时提供边界详细信息
                        if injection.place is None or injection.parameter is None:
                            if place in (PLACE.USER_AGENT, PLACE.REFERER, PLACE.HOST):
                                injection.parameter = place
                            else:
                                injection.parameter = parameter

                            injection.place = place
                            injection.ptype = ptype
                            injection.prefix = prefix
                            injection.suffix = suffix
                            injection.clause = clause

                        # 每当测试成功时提供测试详细信息
                        if hasattr(test, "details"):
                            for key, value in test.details.items():
                                if key == "dbms":
                                    injection.dbms = value

                                    if not isinstance(value, list):
                                        Backend.setDbms(value)
                                    else:
                                        Backend.forceDbms(value[0], True)

                                elif key == "dbms_version" and injection.dbms_version is None and not conf.testFilter:
                                    injection.dbms_version = Backend.setVersion(value)

                                elif key == "os" and injection.os is None:
                                    injection.os = Backend.setOs(value)

                        if vector is None and "vector" in test and test.vector is not None:
                            vector = test.vector

                        injection.data[stype] = AttribDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].templatePayload = templatePayload
                        injection.data[stype].matchRatio = kb.matchRatio
                        injection.data[stype].trueCode = trueCode
                        injection.data[stype].falseCode = falseCode

                        injection.conf.textOnly = conf.textOnly
                        injection.conf.titles = conf.titles
                        injection.conf.code = conf.code
                        injection.conf.string = conf.string
                        injection.conf.notString = conf.notString
                        injection.conf.regexp = conf.regexp
                        injection.conf.optimize = conf.optimize

                        if conf.beep:
                            beep()

                        # 对于其他 <where> 标签，不需要执行此测试
                        break

                if injectable is True:
                    kb.vulnHosts.add(conf.hostname)
                    break

            # 重置强制的后端 DBMS 值
            Backend.flushForcedDbms()

        except KeyboardInterrupt:
            warnMsg = "用户在检测阶段中止"
            logger.warning(warnMsg)

            if conf.multipleTargets:
                msg = "您想如何继续？ [ne(X)t 目标/(s)跳过当前测试/(e)结束检测阶段/(n)下一个参数/(c)更改详细程度/(q)退出]"
                choice = readInput(msg, default='X', checkBatch=False).upper()
            else:
                msg = "您想如何继续？ [(S)跳过当前测试/(e)结束检测阶段/(n)下一个参数/(c)更改详细程度/(q)退出]"
                choice = readInput(msg, default='S', checkBatch=False).upper()

            if choice == 'X':
                if conf.multipleTargets:
                    raise SqlmapSkipTargetException
            elif choice == 'C':
                choice = None
                while not ((choice or "").isdigit() and 0 <= int(choice) <= 6):
                    if choice:
                        logger.warning("无效值")
                    msg = "输入新的详细程度: [0-6] "
                    choice = readInput(msg, default=str(conf.verbose), checkBatch=False)
                conf.verbose = int(choice)
                setVerbosity()
                if hasattr(test.request, "columns") and hasattr(test.request, "_columns"):
                    test.request.columns = test.request._columns
                    delattr(test.request, "_columns")
                tests.insert(0, test)
            elif choice == 'N':
                return None
            elif choice == 'E':
                kb.endDetection = True
            elif choice == 'Q':
                raise SqlmapUserQuitException

        finally:
            # 重置强制的后端 DBMS 值
            Backend.flushForcedDbms()

    Backend.flushForcedDbms(True)

    # 返回注入对象
    if injection.place is not None and injection.parameter is not None:
        if not conf.dropSetCookie and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data and injection.data[PAYLOAD.TECHNIQUE.BOOLEAN].vector.startswith('OR'):
            warnMsg = "在 OR 基于布尔的注入情况下，如果在数据检索过程中遇到任何问题，请考虑使用 '--drop-set-cookie' "
            logger.warning(warnMsg)

        if not checkFalsePositives(injection):
            if conf.hostname in kb.vulnHosts:
                kb.vulnHosts.remove(conf.hostname)
            if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE not in injection.notes:
                injection.notes.append(NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE)
    else:
        injection = None

    if injection and NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE not in injection.notes:
        checkSuhosinPatch(injection)
        checkFilteredChars(injection)

    return injection

@stackedmethod
def heuristicCheckDbms(injection):
    """
    此函数在识别到基于布尔的盲注时调用，
    通过通用有效负载识别，且 DBMS 尚未指纹识别，目的是尝试
    使用简单的 DBMS 特定的布尔测试来识别可能的 DBMS
    """

    retVal = False

    if conf.skipHeuristics:
        return retVal

    pushValue(kb.injection)
    kb.injection = injection

    for dbms in getPublicTypeMembers(DBMS, True):
        randStr1, randStr2 = randomStr(), randomStr()

        Backend.forceDbms(dbms)

        if dbms in HEURISTIC_NULL_EVAL:
            result = checkBooleanExpression("(SELECT %s%s) IS NULL" % (HEURISTIC_NULL_EVAL[dbms], FROM_DUMMY_TABLE.get(dbms, "")))
        elif not ((randStr1 in unescaper.escape("'%s'" % randStr1)) and list(FROM_DUMMY_TABLE.values()).count(FROM_DUMMY_TABLE.get(dbms, "")) != 1):
            result = checkBooleanExpression("(SELECT '%s'%s)=%s%s%s" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), SINGLE_QUOTE_MARKER, randStr1, SINGLE_QUOTE_MARKER))
        else:
            result = False

        if result:
            if not checkBooleanExpression("(SELECT '%s'%s)=%s%s%s" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), SINGLE_QUOTE_MARKER, randStr2, SINGLE_QUOTE_MARKER)):
                retVal = dbms
                break

    Backend.flushForcedDbms()
    kb.injection = popValue()

    if retVal:
        infoMsg = "启发式（扩展）测试显示后端 DBMS "  # 并没有像“解析”同类一样重要（因为误报）
        infoMsg += "可能是 '%s' " % retVal
        logger.info(infoMsg)

        kb.heuristicExtendedDbms = retVal

    return retVal

@stackedmethod
def checkFalsePositives(injection):
    """
    检查误报（仅在单一特殊情况下）
    """

    retVal = True

    if all(_ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED) for _ in injection.data) or (len(injection.data) == 1 and PAYLOAD.TECHNIQUE.UNION in injection.data and "Generic" in injection.data[PAYLOAD.TECHNIQUE.UNION].title):
        pushValue(kb.injection)

        infoMsg = "检查 %s" % injection.place
        infoMsg += " 参数 '%s' 是否为误报" % injection.parameter
        logger.info(infoMsg)

        def _():
            return int(randomInt(2)) + 1

        kb.injection = injection

        for level in xrange(conf.level):
            while True:
                randInt1, randInt2, randInt3 = (_() for j in xrange(3))

                randInt1 = min(randInt1, randInt2, randInt3)
                randInt3 = max(randInt1, randInt2, randInt3)

                if conf.string and any(conf.string in getUnicode(_) for _ in (randInt1, randInt2, randInt3)):
                    continue

                if conf.notString and any(conf.notString in getUnicode(_) for _ in (randInt1, randInt2, randInt3)):
                    continue

                if randInt3 > randInt2 > randInt1:
                    break

            if not checkBooleanExpression("%d%s%d" % (randInt1, INFERENCE_EQUALS_CHAR, randInt1)):
                retVal = False
                break

            if PAYLOAD.TECHNIQUE.BOOLEAN not in injection.data:
                checkBooleanExpression("%d%s%d" % (randInt1, INFERENCE_EQUALS_CHAR, randInt2))          # 以防万一，如果 DBMS 没有正确从先前的延迟请求恢复

            if checkBooleanExpression("%d%s%d" % (randInt1, INFERENCE_EQUALS_CHAR, randInt3)):          # 这不应该评估为 True
                retVal = False
                break

            elif checkBooleanExpression("%d%s%d" % (randInt3, INFERENCE_EQUALS_CHAR, randInt2)):        # 这不应该评估为 True
                retVal = False
                break

            elif not checkBooleanExpression("%d%s%d" % (randInt2, INFERENCE_EQUALS_CHAR, randInt2)):    # 这必须评估为 True
                retVal = False
                break

            elif checkBooleanExpression("%d %d" % (randInt3, randInt2)):                                # 这不应该评估为 True（无效语句）
                retVal = False
                break

        if not retVal:
            warnMsg = "检测到误报或不可利用的注入点"
            logger.warning(warnMsg)

        kb.injection = popValue()

    return retVal

@stackedmethod
def checkSuhosinPatch(injection):
    """
    检查 Suhosin 补丁（和类似）保护机制的存在
    """

    if injection.place in (PLACE.GET, PLACE.URI):
        debugMsg = "检查参数长度 "
        debugMsg += "限制机制"
        logger.debug(debugMsg)

        pushValue(kb.injection)

        kb.injection = injection
        randInt = randomInt()

        if not checkBooleanExpression("%d=%s%d" % (randInt, ' ' * SUHOSIN_MAX_VALUE_LENGTH, randInt)):
            warnMsg = "检测到参数长度限制 "
            warnMsg += "机制（例如 Suhosin 补丁）。 "
            warnMsg += "在枚举阶段可能会出现潜在问题"
            logger.warning(warnMsg)

        kb.injection = popValue()

@stackedmethod
def checkFilteredChars(injection):
    debugMsg = "检查过滤字符"
    logger.debug(debugMsg)

    pushValue(kb.injection)

    kb.injection = injection
    randInt = randomInt()

    # 所有其他技术已经在测试中使用了括号
    if len(injection.data) == 1 and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
        if not checkBooleanExpression("(%d)=%d" % (randInt, randInt)):
            warnMsg = "看起来某些非字母数字字符（即 ()）被 "
            warnMsg += "后端服务器过滤掉。 有很大的可能性 sqlmap 无法 "
            warnMsg += "正确利用此漏洞"
            logger.warning(warnMsg)

    # 推理技术依赖于字符 '>'
    if not any(_ in injection.data for _ in (PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.QUERY)):
        if not checkBooleanExpression("%d>%d" % (randInt + 1, randInt)):
            warnMsg = "看起来字符 '>' 被 "
            warnMsg += "后端服务器过滤掉。 强烈建议您使用 '--tamper=between' 重新运行"
            logger.warning(warnMsg)

    kb.injection = popValue()

def heuristicCheckSqlInjection(place, parameter):
    if conf.skipHeuristics:
        return None

    origValue = conf.paramDict[place][parameter]
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    prefix = ""
    suffix = ""
    randStr = ""

    if conf.prefix or conf.suffix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.suffix:
            suffix = conf.suffix

    while randStr.count('\'') != 1 or randStr.count('\"') != 1:
        randStr = randomStr(length=10, alphabet=HEURISTIC_CHECK_ALPHABET)

    kb.heuristicMode = True

    payload = "%s%s%s" % (prefix, randStr, suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _, code = Request.queryPage(payload, place, content=True, raise404=False)

    kb.heuristicPage = page
    kb.heuristicCode = code
    kb.heuristicMode = False

    parseFilePaths(page)
    result = wasLastResponseDBMSError()

    infoMsg = "启发式（基本）测试表明 %s参数 '%s' 可能 " % ("%s " % paramType if paramType != parameter else "", parameter)

    def _(page):
        return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

    casting = _(page) and not _(kb.originalPage)

    if not casting and not result and kb.dynamicParameter and origValue.isdigit() and not kb.heavilyDynamic:
        randInt = int(randomInt())
        payload = "%s%s%s" % (prefix, "%d-%d" % (int(origValue) + randInt, randInt), suffix)
        payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
        result = Request.queryPage(payload, place, raise404=False)

        if not result:
            randStr = randomStr()
            payload = "%s%s%s" % (prefix, "%s.%d%s" % (origValue, random.randint(1, 9), randStr), suffix)
            payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
            casting = Request.queryPage(payload, place, raise404=False)

    kb.heuristicTest = HEURISTIC_TEST.CASTED if casting else HEURISTIC_TEST.NEGATIVE if not result else HEURISTIC_TEST.POSITIVE

    if kb.heavilyDynamic:
        debugMsg = "由于高度动态性，启发式检查已停止"
        logger.debug(debugMsg)
        return kb.heuristicTest

    if casting:
        errMsg = "检测到可能的 %s 转换（例如，'" % ("整数" if origValue.isdigit() else "类型")

        platform = conf.url.split('.')[-1].lower()
        if platform == WEB_PLATFORM.ASP:
            errMsg += "%s=CInt(request.querystring(\"%s\"))" % (parameter, parameter)
        elif platform == WEB_PLATFORM.ASPX:
            errMsg += "int.TryParse(Request.QueryString[\"%s\"], out %s)" % (parameter, parameter)
        elif platform == WEB_PLATFORM.JSP:
            errMsg += "%s=Integer.parseInt(request.getParameter(\"%s\"))" % (parameter, parameter)
        else:
            errMsg += "$%s=intval($_REQUEST[\"%s\"])" % (parameter, parameter)

        errMsg += "') 在后端网页应用程序中"
        logger.error(errMsg)

        if kb.ignoreCasted is None:
            message = "您想跳过这种情况（并节省扫描时间）吗？ %s " % ("[Y/n]" if conf.multipleTargets else "[y/N]")
            kb.ignoreCasted = readInput(message, default='Y' if conf.multipleTargets else 'N', boolean=True)

    elif result:
        infoMsg += "可能是可注入的"
        if Backend.getErrorParsedDBMSes():
            infoMsg += "（可能的 DBMS: '%s'）" % Format.getErrorParsedDBMSes()
        logger.info(infoMsg)

    else:
        infoMsg += "不可注入"
        logger.warning(infoMsg)

    kb.heuristicMode = True
    kb.disableHtmlDecoding = True

    randStr1, randStr2 = randomStr(NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH), randomStr(NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH)
    value = "%s%s%s" % (randStr1, DUMMY_NON_SQLI_CHECK_APPENDIX, randStr2)
    payload = "%s%s%s" % (prefix, "'%s" % value, suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _, _ = Request.queryPage(payload, place, content=True, raise404=False)

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    # 参考: https://bugs.python.org/issue18183
    if value.upper() in (page or "").upper():
        infoMsg = "启发式（XSS）测试表明 %s参数 '%s' 可能受到跨站脚本（XSS）攻击" % ("%s " % paramType if paramType != parameter else "", parameter)
        logger.info(infoMsg)

        if conf.beep:
            beep()

    for match in re.finditer(FI_ERROR_REGEX, page or ""):
        if randStr1.lower() in match.group(0).lower():
            infoMsg = "启发式（FI）测试表明 %s参数 '%s' 可能受到文件包含（FI）攻击" % ("%s " % paramType if paramType != parameter else "", parameter)
            logger.info(infoMsg)

            if conf.beep:
                beep()

            break

    kb.disableHtmlDecoding = False
    kb.heuristicMode = False

    return kb.heuristicTest

def checkDynParam(place, parameter, value):
    """
    此函数检查 URL 参数是否动态。如果动态，则页面内容不同，
    否则动态性可能取决于另一个参数。
    """

    if kb.choices.redirect:
        return None

    kb.matchRatio = None
    dynResult = None
    randInt = randomInt()

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    infoMsg = "测试 %s参数 '%s' 是否动态" % ("%s " % paramType if paramType != parameter else "", parameter)
    logger.info(infoMsg)

    try:
        payload = agent.payload(place, parameter, value, getUnicode(randInt))
        dynResult = Request.queryPage(payload, place, raise404=False)
    except SqlmapConnectionException:
        pass

    result = None if dynResult is None else not dynResult
    kb.dynamicParameter = result

    return result

def checkDynamicContent(firstPage, secondPage):
    """
    此函数检查提供的页面中的动态内容
    """

    if kb.nullConnection:
        debugMsg = "跳过动态内容检查 "
        debugMsg += "因为使用了 NULL 连接"
        logger.debug(debugMsg)
        return

    if any(page is None for page in (firstPage, secondPage)):
        warnMsg = "无法检查动态内容 "
        warnMsg += "因为缺少页面内容"
        logger.critical(warnMsg)
        return

    if firstPage and secondPage and any(len(_) > MAX_DIFFLIB_SEQUENCE_LENGTH for _ in (firstPage, secondPage)):
        ratio = None
    else:
        try:
            seqMatcher = getCurrentThreadData().seqMatcher
            seqMatcher.set_seq1(firstPage)
            seqMatcher.set_seq2(secondPage)
            ratio = seqMatcher.quick_ratio()
        except MemoryError:
            ratio = None

    if ratio is None:
        kb.skipSeqMatcher = True

    # 如果差异不可接受，则启动动态移除引擎
    elif ratio <= UPPER_RATIO_BOUND:
        findDynamicContent(firstPage, secondPage)

        count = 0
        while not Request.queryPage():
            count += 1

            if count > conf.retries:
                warnMsg = "目标 URL 内容似乎过于动态。 "
                warnMsg += "正在切换到 '--text-only' "
                logger.warning(warnMsg)

                conf.textOnly = True
                return

            warnMsg = "目标 URL 内容似乎非常动态。 "
            warnMsg += "sqlmap 将重试请求"
            singleTimeLogMessage(warnMsg, logging.CRITICAL)

            kb.heavilyDynamic = True

            secondPage, _, _ = Request.queryPage(content=True)
            findDynamicContent(firstPage, secondPage)

def checkStability():
    """
    此函数通过在每次请求之间稍作延迟请求同一页面两次来检查 URL 内容是否稳定
    假设页面是稳定的。

    如果请求同一页面时，内容不同，则可能动态性取决于其他参数，
    比如字符串匹配（--string）。
    """

    infoMsg = "测试目标 URL 内容是否稳定"
    logger.info(infoMsg)

    firstPage = kb.originalPage  # 在 checkConnection() 中设置

    delay = MAX_STABILITY_DELAY - (time.time() - (kb.originalPageTime or 0))
    delay = max(0, min(MAX_STABILITY_DELAY, delay))
    time.sleep(delay)

    secondPage, _, _ = Request.queryPage(content=True, noteResponseTime=False, raise404=False)

    if kb.choices.redirect:
        return None

    kb.pageStable = (firstPage == secondPage)

    if kb.pageStable:
        if firstPage:
            infoMsg = "目标 URL 内容是稳定的"
            logger.info(infoMsg)
        else:
            errMsg = "由于缺乏内容，检查页面稳定性时出现错误。请检查 "
            errMsg += "页面请求结果（和可能的错误）使用更高的详细程度"
            logger.error(errMsg)

    else:
        warnMsg = "目标 URL 内容不稳定（即内容不同）。 sqlmap 将基于序列匹配器比较页面。如果没有检测到动态或可注入参数，或出现垃圾结果，请参考用户手册中的 '页面比较' 段落"
        logger.warning(warnMsg)

        message = "您想如何继续？ [(C)继续/(s)字符串/(r)正则表达式/(q)退出] "
        choice = readInput(message, default='C').upper()

        if choice == 'Q':
            raise SqlmapUserQuitException

        elif choice == 'S':
            showStaticWords(firstPage, secondPage)

            message = "请输入参数的字符串值 'string': "
            string = readInput(message)

            if string:
                conf.string = string

                if kb.nullConnection:
                    debugMsg = "因字符串检查，关闭 NULL 连接 "
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "提供的值为空"
                raise SqlmapNoneDataException(errMsg)

        elif choice == 'R':
            message = "请输入参数的正则表达式值 'regex': "
            regex = readInput(message)

            if regex:
                conf.regex = regex

                if kb.nullConnection:
                    debugMsg = "因正则表达式检查，关闭 NULL 连接 "
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "提供的值为空"
                raise SqlmapNoneDataException(errMsg)

        else:
            checkDynamicContent(firstPage, secondPage)

    return kb.pageStable

@stackedmethod
def checkWaf():
    """
    参考: http://seclists.org/nmap-dev/2011/q2/att-1005/http-waf-detect.nse
    """

    if any((conf.string, conf.notString, conf.regexp, conf.dummy, conf.offline, conf.skipWaf)):
        return None

    if kb.originalCode == _http_client.NOT_FOUND:
        return None

    _ = hashDBRetrieve(HASHDB_KEYS.CHECK_WAF_RESULT, True)
    if _ is not None:
        if _:
            warnMsg = "先前的启发式检测到目标 "
            warnMsg += "受到某种类型的 WAF/IPS 保护"
            logger.critical(warnMsg)
        return _

    if not kb.originalPage:
        return None

    infoMsg = "检查目标是否受某种 WAF/IPS "
    infoMsg += "保护"
    logger.info(infoMsg)

    retVal = False
    payload = "%d %s" % (randomInt(), IPS_WAF_CHECK_PAYLOAD)

    place = PLACE.GET
    if PLACE.URI in conf.parameters:
        value = "%s=%s" % (randomStr(), agent.addPayloadDelimiters(payload))
    else:
        value = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + DEFAULT_GET_POST_DELIMITER
        value += "%s=%s" % (randomStr(), agent.addPayloadDelimiters(payload))

    pushValue(kb.choices.redirect)
    pushValue(kb.resendPostOnRedirect)
    pushValue(conf.timeout)

    kb.choices.redirect = REDIRECTION.YES
    kb.resendPostOnRedirect = False
    conf.timeout = IPS_WAF_CHECK_TIMEOUT

    try:
        retVal = (Request.queryPage(place=place, value=value, getRatioValue=True, noteResponseTime=False, silent=True, raise404=False, disableTampering=True)[1] or 0) < IPS_WAF_CHECK_RATIO
    except SqlmapConnectionException:
        retVal = True
    finally:
        kb.matchRatio = None

        conf.timeout = popValue()
        kb.resendPostOnRedirect = popValue()
        kb.choices.redirect = popValue()

    hashDBWrite(HASHDB_KEYS.CHECK_WAF_RESULT, retVal, True)

    if retVal:
        if not kb.identifiedWafs:
            warnMsg = "启发式检测到目标 "
            warnMsg += "受到某种类型的 WAF/IPS 保护"
            logger.critical(warnMsg)

        message = "您确定要继续进行更多目标测试吗？ [Y/n] "
        choice = readInput(message, default='Y', boolean=True)

        if not choice:
            raise SqlmapUserQuitException
        else:
            if not conf.tamper:
                warnMsg = "请考虑使用转介脚本（选项 '--tamper'）"
                singleTimeWarnMessage(warnMsg)

    return retVal

@stackedmethod
def checkNullConnection():
    """
    参考: http://www.wisec.it/sectou.php?id=472f952d79293
    """

    if conf.data:
        return False

    _ = hashDBRetrieve(HASHDB_KEYS.CHECK_NULL_CONNECTION_RESULT, True)
    if _ is not None:
        kb.nullConnection = _

        if _:
            dbgMsg = "恢复 NULL 连接方法 '%s'" % _
            logger.debug(dbgMsg)

    else:
        infoMsg = "测试 NULL 连接到目标 URL"
        logger.info(infoMsg)

        pushValue(kb.pageCompress)
        kb.pageCompress = False

        try:
            page, headers, _ = Request.getPage(method=HTTPMETHOD.HEAD, raise404=False)

            if not page and HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
                kb.nullConnection = NULLCONNECTION.HEAD

                infoMsg = "NULL 连接通过 HEAD 方法（'Content-Length'）得以支持"
                logger.info(infoMsg)
            else:
                page, headers, _ = Request.getPage(auxHeaders={HTTP_HEADER.RANGE: "bytes=-1"})

                if page and len(page) == 1 and HTTP_HEADER.CONTENT_RANGE in (headers or {}):
                    kb.nullConnection = NULLCONNECTION.RANGE

                    infoMsg = "NULL 连接通过 GET 方法（'Range'）得以支持"
                    logger.info(infoMsg)
                else:
                    _, headers, _ = Request.getPage(skipRead=True)

                    if HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
                        kb.nullConnection = NULLCONNECTION.SKIP_READ

                        infoMsg = "NULL 连接通过 'skip-read' 方法得以支持"
                        logger.info(infoMsg)

        except SqlmapConnectionException:
            pass

        finally:
            kb.pageCompress = popValue()
            kb.nullConnection = False if kb.nullConnection is None else kb.nullConnection
            hashDBWrite(HASHDB_KEYS.CHECK_NULL_CONNECTION_RESULT, kb.nullConnection, True)

    return kb.nullConnection in getPublicTypeMembers(NULLCONNECTION, True)

def checkConnection(suppressOutput=False):
    threadData = getCurrentThreadData()

    if not re.search(r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z", conf.hostname):
        if not any((conf.proxy, conf.tor, conf.dummy, conf.offline)):
            try:
                debugMsg = "解析主机名 '%s'" % conf.hostname
                logger.debug(debugMsg)
                socket.getaddrinfo(conf.hostname, None)
            except socket.gaierror:
                errMsg = "主机 '%s' 不存在" % conf.hostname
                raise SqlmapConnectionException(errMsg)
            except socket.error as ex:
                errMsg = "处理时发生问题 "
                errMsg += "解析主机名 '%s' ('%s')" % (conf.hostname, getSafeExString(ex))
                raise SqlmapConnectionException(errMsg)
            except UnicodeError as ex:
                errMsg = "处理时发生问题 "
                errMsg += "处理主机名 '%s' ('%s')" % (conf.hostname, getSafeExString(ex))
                raise SqlmapDataException(errMsg)

    if not suppressOutput and not conf.dummy and not conf.offline:
        infoMsg = "测试与目标 URL 的连接"
        logger.info(infoMsg)

    try:
        kb.originalPageTime = time.time()
        page, headers, _ = Request.queryPage(content=True, noteResponseTime=False)

        rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

        if conf.string:
            infoMsg = "测试提供的字符串是否在目标 URL 页面内容中"
            logger.info(infoMsg)

            if conf.string not in rawResponse:
                warnMsg = "您提供了 '%s' 作为要 " % conf.string
                warnMsg += "匹配的字符串，但该字符串不在目标 "
                warnMsg += "URL 原始响应中，sqlmap 将照常继续"
                logger.warning(warnMsg)

        if conf.regexp:
            infoMsg = "测试提供的正则表达式是否匹配目标 URL 页面内容"
            logger.info(infoMsg)

            if not re.search(conf.regexp, rawResponse, re.I | re.M):
                warnMsg = "您提供了 '%s' 作为正则表达式 " % conf.regexp
                warnMsg += "但在目标 URL 原始响应中没有匹配项。 sqlmap "
                warnMsg += "将照常继续"
                logger.warning(warnMsg)

        kb.errorIsNone = False

        if any(_ in (kb.serverHeader or "") for _ in PRECONNECT_INCOMPATIBLE_SERVERS):
            singleTimeWarnMessage("关闭预连接机制，因为与不兼容服务器 ('%s')" % kb.serverHeader)
            conf.disablePrecon = True

        if not kb.originalPage and wasLastResponseHTTPError():
            if getLastRequestHTTPError() not in (conf.ignoreCode or []):
                errMsg = "无法检索页面内容"
                raise SqlmapConnectionException(errMsg)
        elif wasLastResponseDBMSError():
            warnMsg = "在 HTTP 响应体中发现 DBMS 错误 "
            warnMsg += "可能会干扰测试结果"
            logger.warning(warnMsg)
        elif wasLastResponseHTTPError():
            if getLastRequestHTTPError() not in (conf.ignoreCode or []):
                warnMsg = "Web 服务器返回 HTTP 错误代码 (%d) " % getLastRequestHTTPError()
                warnMsg += "可能会干扰测试结果"
                logger.warning(warnMsg)
        else:
            kb.errorIsNone = True

        if kb.choices.redirect == REDIRECTION.YES and threadData.lastRedirectURL and threadData.lastRedirectURL[0] == threadData.lastRequestUID:
            if (threadData.lastRedirectURL[1] or "").startswith("https://") and conf.hostname in getUnicode(threadData.lastRedirectURL[1]):
                conf.url = re.sub(r"https?://", "https://", conf.url)
                match = re.search(r":(\d+)", threadData.lastRedirectURL[1])
                port = match.group(1) if match else 443
                conf.url = re.sub(r":\d+(/|\Z)", r":%s\g<1>" % port, conf.url)

    except SqlmapConnectionException as ex:
        if conf.ipv6:
            warnMsg = "请使用类似 ping6 "
            warnMsg += "的工具检查连接到提供的 " 
            warnMsg += "IPv6 地址 (例如 'ping6 -I eth0 %s')" % conf.hostname
            warnMsg += "以避免 "
            warnMsg += "任何地址问题"
            singleTimeWarnMessage(warnMsg)

        if any(code in kb.httpErrorCodes for code in (_http_client.NOT_FOUND, )):
            errMsg = getSafeExString(ex)
            logger.critical(errMsg)

            if conf.multipleTargets:
                return False

            msg = "在这种情况下继续并不推荐。您想退出以确保所有设置正确吗？ [Y/n] "
            if readInput(msg, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                kb.ignoreNotFound = True
        else:
            raise
    finally:
        kb.originalPage = kb.pageTemplate = threadData.lastPage
        kb.originalCode = threadData.lastCode

    if conf.cj and not conf.cookie and not any(_[0] == HTTP_HEADER.COOKIE for _ in conf.httpHeaders) and not conf.dropSetCookie:
        candidate = DEFAULT_COOKIE_DELIMITER.join("%s=%s" % (_.name, _.value) for _ in conf.cj)

        message = "您尚未声明 cookie，虽然 "
        message += "服务器希望设置自己的 ('%s')。 " % re.sub(r"(=[^=;]{10}[^=;])[^=;]+([^=;]{10})", r"\g<1>...\g<2>", candidate)
        message += "您想使用这些吗？ [Y/n] "
        if readInput(message, default='Y', boolean=True):
            kb.mergeCookies = True
            conf.httpHeaders.append((HTTP_HEADER.COOKIE, candidate))

    return True

def checkInternet():
    content = Request.getPage(url=CHECK_INTERNET_ADDRESS, checking=True)[0]
    return CHECK_INTERNET_VALUE in (content or "")

def setVerbosity():  # 交叉引用函数
    raise NotImplementedError
