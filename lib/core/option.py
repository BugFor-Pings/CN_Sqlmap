#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import codecs
import functools
import glob
import inspect
import logging
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import traceback

from lib.controller.checks import checkConnection
from lib.core.common import Backend
from lib.core.common import boldifyMessage
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import decodeStringEscape
from lib.core.common import fetchRandomAgent
from lib.core.common import filterNone
from lib.core.common import findLocalPort
from lib.core.common import findPageForms
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getFileType
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import intersect
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import openFile
from lib.core.common import parseRequestFile
from lib.core.common import parseTargetDirect
from lib.core.common import paths
from lib.core.common import randomStr
from lib.core.common import readCachedFileContent
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.common import runningAsAdmin
from lib.core.common import safeExpandUser
from lib.core.common import safeFilepathEncode
from lib.core.common import saveConfig
from lib.core.common import setColor
from lib.core.common import setOptimize
from lib.core.common import setPaths
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urldecode
from lib.core.compat import cmp
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import queries
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.datatype import OrderedSet
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DUMP_FORMAT
from lib.core.enums import FORK
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import MOBILES
from lib.core.enums import OPTION_TYPE
from lib.core.enums import PAYLOAD
from lib.core.enums import PRIORITY
from lib.core.enums import PROXY_TYPE
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import WIZARD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.log import FORMATTER
from lib.core.optiondict import optDict
from lib.core.settings import CODECS_LIST_PAGE
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_ALIASES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DEFAULT_TOR_HTTP_PORTS
from lib.core.settings import DEFAULT_TOR_SOCKS_PORTS
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.settings import IS_WIN
from lib.core.settings import KB_CHARS_BOUNDARY_CHAR
from lib.core.settings import KB_CHARS_LOW_FREQUENCY_ALPHABET
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_CONNECT_RETRIES
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.settings import PRECONNECT_CANDIDATE_TIMEOUT
from lib.core.settings import PROXY_ENVIRONMENT_VARIABLES
from lib.core.settings import SOCKET_PRE_CONNECT_QUEUE_SIZE
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import SUPPORTED_OS
from lib.core.settings import TIME_DELAY_CANDIDATES
from lib.core.settings import UNION_CHAR_REGEX
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.threads import getCurrentThreadData
from lib.core.threads import setDaemon
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.parse.payloads import loadBoundaries
from lib.parse.payloads import loadPayloads
from lib.request.basic import checkCharEncoding
from lib.request.basicauthhandler import SmartHTTPBasicAuthHandler
from lib.request.chunkedhandler import ChunkedHandler
from lib.request.connect import Connect as Request
from lib.request.dns import DNSServer
from lib.request.httpshandler import HTTPSHandler
from lib.request.pkihandler import HTTPSPKIAuthHandler
from lib.request.rangehandler import HTTPRangeHandler
from lib.request.redirecthandler import SmartRedirectHandler
from lib.utils.crawler import crawl
from lib.utils.deps import checkDependencies
from lib.utils.har import HTTPCollectorFactory
from lib.utils.purge import purge
from lib.utils.search import search
from thirdparty import six
from thirdparty.keepalive import keepalive
from thirdparty.multipart import multipartpost
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import http_cookiejar as _http_cookiejar
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks
from xml.etree.ElementTree import ElementTree

authHandler = _urllib.request.BaseHandler()
chunkedHandler = ChunkedHandler()
httpsHandler = HTTPSHandler()
keepAliveHandler = keepalive.HTTPHandler()
proxyHandler = _urllib.request.ProxyHandler()
redirectHandler = SmartRedirectHandler()
rangeHandler = HTTPRangeHandler()
multipartPostHandler = multipartpost.MultipartPostHandler()

# Reference: https://mail.python.org/pipermail/python-list/2009-November/558615.html
try:
    WindowsError
except NameError:
    WindowsError = None

def _loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """

    def iterate(node, retVal=None):
        class DictObject(object):
            def __init__(self):
                self.__dict__ = {}

            def __contains__(self, name):
                return name in self.__dict__

        if retVal is None:
            retVal = DictObject()

        for child in node.findall("*"):
            instance = DictObject()
            retVal.__dict__[child.tag] = instance
            if child.attrib:
                instance.__dict__.update(child.attrib)
            else:
                iterate(child, instance)

        return retVal

    tree = ElementTree()
    try:
        tree.parse(paths.QUERIES_XML)
    except Exception as ex:
        errMsg = "似乎有什么问题 "
        errMsg += "文件 '%s' ('%s'). 请制作 " % (paths.QUERIES_XML, getSafeExString(ex))
        errMsg += "确保您没有对其进行任何更改"
        raise SqlmapInstallationException(errMsg)

    for node in tree.findall("*"):
        queries[node.attrib['value']] = iterate(node)

def _setMultipleTargets():
    """
    Define a configuration parameter if we are running in multiple target
    mode.
    """

    initialTargetsCount = len(kb.targets)
    seen = set()

    if not conf.logFile:
        return

    debugMsg = "分析目标列表 '%s'" % conf.logFile
    logger.debug(debugMsg)

    if not os.path.exists(conf.logFile):
        errMsg = "指定的目标列表不存在"
        raise SqlmapFilePathException(errMsg)

    if checkFile(conf.logFile, False):
        for target in parseRequestFile(conf.logFile):
            url, _, data, _, _ = target
            key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
            if key not in seen:
                kb.targets.add(target)
                seen.add(key)

    elif os.path.isdir(conf.logFile):
        files = os.listdir(conf.logFile)
        files.sort()

        for reqFile in files:
            if not re.search(r"([\d]+)\-request", reqFile):
                continue

            for target in parseRequestFile(os.path.join(conf.logFile, reqFile)):
                url, _, data, _, _ = target
                key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
                if key not in seen:
                    kb.targets.add(target)
                    seen.add(key)

    else:
        errMsg = "指定的目标列表不是文件 "
        errMsg += "也不是目录"
        raise SqlmapFilePathException(errMsg)

    updatedTargetsCount = len(kb.targets)

    if updatedTargetsCount > initialTargetsCount:
        infoMsg = "sqlmap已解析 %d " % (updatedTargetsCount - initialTargetsCount)
        infoMsg += "(参数唯一) 来自的请求 "
        infoMsg += "准备测试的目标列表"
        logger.info(infoMsg)

def _adjustLoggingFormatter():
    """
    Solves problem of line deletition caused by overlapping logging messages
    and retrieved data info in inference mode
    """

    if hasattr(FORMATTER, '_format'):
        return

    def format(record):
        message = FORMATTER._format(record)
        message = boldifyMessage(message)
        if kb.get("prependFlag"):
            message = "\n%s" % message
            kb.prependFlag = False
        return message

    FORMATTER._format = FORMATTER.format
    FORMATTER.format = format

def _setRequestFromFile():
    """
    This function checks if the way to make a HTTP request is through supplied
    textual file, parses it and saves the information into the knowledge base.
    """

    if conf.requestFile:
        for requestFile in re.split(PARAMETER_SPLITTING_REGEX, conf.requestFile):
            requestFile = safeExpandUser(requestFile)
            url = None
            seen = set()

            if not checkFile(requestFile, False):
                errMsg = "指定的HTTP请求文件 '%s' " % requestFile
                errMsg += "不存在"
                raise SqlmapFilePathException(errMsg)

            infoMsg = "解析来自的HTTP请求 '%s'" % requestFile
            logger.info(infoMsg)

            for target in parseRequestFile(requestFile):
                url = target[0]
                if url not in seen:
                    kb.targets.add(target)
                    if len(kb.targets) > 1:
                        conf.multipleTargets = True
                    seen.add(url)

            if url is None:
                errMsg = "指定的文件 '%s' " % requestFile
                errMsg += "不包含可用的HTTP请求 (带有参数)"
                raise SqlmapDataException(errMsg)

    if conf.secondReq:
        conf.secondReq = safeExpandUser(conf.secondReq)

        if not checkFile(conf.secondReq, False):
            errMsg = "指定的二阶HTTP请求文件 '%s' " % conf.secondReq
            errMsg += "不存在"
            raise SqlmapFilePathException(errMsg)

        infoMsg = "解析来自的二阶HTTP请求 '%s'" % conf.secondReq
        logger.info(infoMsg)

        try:
            target = next(parseRequestFile(conf.secondReq, False))
            kb.secondReq = target
        except StopIteration:
            errMsg = "指定的二阶HTTP请求文件 '%s' " % conf.secondReq
            errMsg += "不包含有效的HTTP请求"
            raise SqlmapDataException(errMsg)

def _setCrawler():
    if not conf.crawlDepth:
        return

    if not conf.bulkFile:
        if conf.url:
            crawl(conf.url)
        elif conf.requestFile and kb.targets:
            target = next(iter(kb.targets))
            crawl(target[0], target[2], target[3])

def _doSearch():
    """
    This function performs search dorking, parses results
    and saves the testable hosts into the knowledge base.
    """

    if not conf.googleDork:
        return

    kb.data.onlyGETs = None

    def retrieve():
        links = search(conf.googleDork)

        if not links:
            errMsg = "无法找到搜索 "
            errMsg += "dork表达式的结果"
            raise SqlmapGenericException(errMsg)

        for link in links:
            link = urldecode(link)
            if re.search(r"(.*?)\?(.+)", link) or conf.forms:
                kb.targets.add((link, conf.method, conf.data, conf.cookie, None))
            elif re.search(URI_INJECTABLE_REGEX, link, re.I):
                if kb.data.onlyGETs is None and conf.data is None and not conf.googleDork:
                    message = "是否只扫描包含GET参数的结果？ [Y/n] "
                    kb.data.onlyGETs = readInput(message, default='Y', boolean=True)
                if not kb.data.onlyGETs or conf.googleDork:
                    kb.targets.add((link, conf.method, conf.data, conf.cookie, None))

        return links

    while True:
        links = retrieve()

        if kb.targets:
            infoMsg = "找到 %d 个 " % len(links)
            infoMsg += "搜索dork表达式的结果"

            if not conf.forms:
                infoMsg += ", "

                if len(links) == len(kb.targets):
                    infoMsg += "all "
                else:
                    infoMsg += "%d " % len(kb.targets)

                infoMsg += "其中一些是可测试的目标"

            logger.info(infoMsg)
            break

        else:
            message = "找到 %d 结果 " % len(links)
            message += "对于您的search dork表达式， "
            message += "但它们都没有GET参数来测试SQL注入. "
            message += "是否要跳到下一个结果页？ [Y/n]"

            if not readInput(message, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                conf.googlePage += 1

def _setStdinPipeTargets():
    if conf.url:
        return

    if isinstance(conf.stdinPipe, _collections.Iterable):
        infoMsg = "使用'STDIN'分析目标列表"
        logger.info(infoMsg)

        class _(object):
            def __init__(self):
                self.__rest = OrderedSet()

            def __iter__(self):
                return self

            def __next__(self):
                return self.next()

            def next(self):
                try:
                    line = next(conf.stdinPipe)
                except (IOError, OSError, TypeError):
                    line = None

                if line:
                    match = re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", line, re.I)
                    if match:
                        return (match.group(0), conf.method, conf.data, conf.cookie, None)
                elif self.__rest:
                    return self.__rest.pop()

                raise StopIteration()

            def add(self, elem):
                self.__rest.add(elem)

        kb.targets = _()

def _setBulkMultipleTargets():
    if not conf.bulkFile:
        return

    conf.bulkFile = safeExpandUser(conf.bulkFile)

    infoMsg = "分析多个目标列表 '%s'" % conf.bulkFile
    logger.info(infoMsg)

    if not checkFile(conf.bulkFile, False):
        errMsg = "指定的大容量文件 "
        errMsg += "不存在"
        raise SqlmapFilePathException(errMsg)

    found = False
    for line in getFileItems(conf.bulkFile):
        if conf.scope and not re.search(conf.scope, line, re.I):
            continue

        if re.match(r"[^ ]+\?(.+)", line, re.I) or kb.customInjectionMark in line or conf.data:
            found = True
            kb.targets.add((line.strip(), conf.method, conf.data, conf.cookie, None))

    if not found and not conf.forms and not conf.crawlDepth:
        warnMsg = "找不到可用链接（带GET参数）"
        logger.warning(warnMsg)

def _findPageForms():
    if not conf.forms or conf.crawlDepth:
        return

    if conf.url and not checkConnection():
        return

    found = False
    infoMsg = "搜索表单"
    logger.info(infoMsg)

    if not any((conf.bulkFile, conf.googleDork)):
        page, _, _ = Request.queryPage(content=True, ignoreSecondOrder=True)
        if findPageForms(page, conf.url, True, True):
            found = True
    else:
        if conf.bulkFile:
            targets = getFileItems(conf.bulkFile)
        elif conf.googleDork:
            targets = [_[0] for _ in kb.targets]
            kb.targets.clear()
        else:
            targets = []

        for i in xrange(len(targets)):
            try:
                target = targets[i].strip()

                if not re.search(r"(?i)\Ahttp[s]*://", target):
                    target = "http://%s" % target

                page, _, _ = Request.getPage(url=target.strip(), cookie=conf.cookie, crawling=True, raise404=False)
                if findPageForms(page, target, False, True):
                    found = True

                if conf.verbose in (1, 2):
                    status = '%d/%d 访问的链接 (%d%%)' % (i + 1, len(targets), round(100.0 * (i + 1) / len(targets)))
                    dataToStdout("\r[%s] [信息] %s" % (time.strftime("%X"), status), True)
            except KeyboardInterrupt:
                break
            except Exception as ex:
                errMsg = "在搜索表单时出现问题 '%s' ('%s')" % (target, getSafeExString(ex))
                logger.error(errMsg)

    if not found:
        warnMsg = "未找到表单"
        logger.warning(warnMsg)

def _setDBMSAuthentication():
    """
    Check and set the DBMS authentication credentials to run statements as
    another user, not the session user
    """

    if not conf.dbmsCred:
        return

    debugMsg = "设置DBMS身份验证凭据"
    logger.debug(debugMsg)

    match = re.search(r"^(.+?):(.*?)$", conf.dbmsCred)

    if not match:
        errMsg = "DBMS身份验证凭据值的格式必须为 "
        errMsg += "username:password"
        raise SqlmapSyntaxException(errMsg)

    conf.dbmsUsername = match.group(1)
    conf.dbmsPassword = match.group(2)

def _setMetasploit():
    if not conf.osPwn and not conf.osSmb and not conf.osBof:
        return

    debugMsg = "设置带外接管功能"
    logger.debug(debugMsg)

    msfEnvPathExists = False

    if IS_WIN:
        try:
            __import__("win32file")
        except ImportError:
            errMsg = "sqlmap需要第三方模块 'pywin32' "
            errMsg += "为了在windows上使用Metasploit功能. "
            errMsg += " 您可以从 "
            errMsg += "'https://github.com/mhammond/pywin32'"
            raise SqlmapMissingDependence(errMsg)

        if not conf.msfPath:
            for candidate in os.environ.get("PATH", "").split(';'):
                if all(_ in candidate for _ in ("metasploit", "bin")):
                    conf.msfPath = os.path.dirname(candidate.rstrip('\\'))
                    break

    if conf.osSmb:
        isAdmin = runningAsAdmin()

        if not isAdmin:
            errMsg = "如果要执行SMB中继攻击 "
            errMsg += "，需要以管理员身份运行sqlmap "
            errMsg += "，因为它需要在用户指定的 "
            errMsg += "SMB TCP端口上侦听传入连接尝试"
            raise SqlmapMissingPrivileges(errMsg)

    if conf.msfPath:
        for path in (conf.msfPath, os.path.join(conf.msfPath, "bin")):
            if any(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                conf.msfPath = path
                break

        if msfEnvPathExists:
            debugMsg = "提供的Metasploit Framework路径 "
            debugMsg += "'%s' 有效" % conf.msfPath
            logger.debug(debugMsg)
        else:
            warnMsg = "提供的Metasploit Framework路径 "
            warnMsg += "'%s' 无效. 原因可能 " % conf.msfPath
            warnMsg += "路径不存在 "
            warnMsg += "或者需要一个或多个Metasploit可执行文件 "
            warnMsg += "在 msfcli, msfconsole, msfencode 和 "
            warnMsg += "msfpayload 不存在"
            logger.warning(warnMsg)
    else:
        warnMsg = "您没有提供安装Metasploit Framework"
        warnMsg += "的本地路径"
        logger.warning(warnMsg)

    if not msfEnvPathExists:
        warnMsg = "sqlmap将在环境路径中查找 "
        warnMsg += "Metasploit Framework安装"
        logger.warning(warnMsg)

        envPaths = os.environ.get("PATH", "").split(";" if IS_WIN else ":")

        for envPath in envPaths:
            envPath = envPath.replace(";", "")

            if any(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                if msfEnvPathExists:
                    infoMsg = "已找到Metasploit框架"
                    infoMsg += "安装在 '%s' 路径" % envPath
                    logger.info(infoMsg)

                    conf.msfPath = envPath

                    break

    if not msfEnvPathExists:
        errMsg = "无法找到Metasploit Framework安装. "
        errMsg += "你可以在 'https://www.metasploit.com/download/'"
        raise SqlmapFilePathException(errMsg)

def _setWriteFile():
    if not conf.fileWrite:
        return

    debugMsg = "设置写文件功能"
    logger.debug(debugMsg)

    if not os.path.exists(conf.fileWrite):
        errMsg = "提供的本地文件 '%s' 不存在" % conf.fileWrite
        raise SqlmapFilePathException(errMsg)

    if not conf.fileDest:
        errMsg = "您没有提供后端DBMS绝对路径"
        errMsg += "要写入本地文件的位置 '%s'" % conf.fileWrite
        raise SqlmapMissingMandatoryOptionException(errMsg)

    conf.fileWriteType = getFileType(conf.fileWrite)

def _setOS():
    """
    Force the back-end DBMS operating system option.
    """

    if not conf.os:
        return

    if conf.os.lower() not in SUPPORTED_OS:
        errMsg = "您提供了不受支持的后端DBMS操作 "
        errMsg += "系统. 用于操作系统和文件系统访问的受支持 "
        errMsg += "的DBMS操作系统包括 %s. " % ', '.join([o.capitalize() for o in SUPPORTED_OS])
        errMsg += "如果您不知道后端DBMS底层操作系统, "
        errMsg += "不提供它，sqlmap将为您识别它 "
        errMsg += "它."
        raise SqlmapUnsupportedDBMSException(errMsg)

    debugMsg = "强制后端DBMS操作系统由用户定义 "
    debugMsg += "值 '%s'" % conf.os
    logger.debug(debugMsg)

    Backend.setOs(conf.os)

def _setTechnique():
    validTechniques = sorted(getPublicTypeMembers(PAYLOAD.TECHNIQUE), key=lambda x: x[1])
    validLetters = [_[0][0].upper() for _ in validTechniques]

    if conf.technique and isinstance(conf.technique, six.string_types):
        _ = []

        for letter in conf.technique.upper():
            if letter not in validLetters:
                errMsg = "--technique的值必须是由字母 "
                errMsg += "%s组成的字符串。请参阅" % ", ".join(validLetters)
                errMsg += "详细用户手册"
                raise SqlmapSyntaxException(errMsg)

            for validTech, validInt in validTechniques:
                if letter == validTech[0]:
                    _.append(validInt)
                    break

        conf.technique = _

def _setDBMS():
    """
    Force the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "强制后端DBMS为用户定义的值"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    regex = re.search(r"%s ([\d\.]+)" % ("(%s)" % "|".join(SUPPORTED_DBMS)), conf.dbms, re.I)

    if regex:
        conf.dbms = regex.group(1)
        Backend.setVersion(regex.group(2))

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg = "您提供了不受支持的后端数据库管理 "
        errMsg += "系统. 支持的DBMS如下： %s. " % ', '.join(sorted((_ for _ in (list(DBMS_DICT) + getPublicTypeMembers(FORK, True))), key=str.lower))
        errMsg += "如果您不知道后端DBMS，请不要提供它， "
        errMsg += "sqlmap将为您提供指纹."
        raise SqlmapUnsupportedDBMSException(errMsg)

    for dbms, aliases in DBMS_ALIASES:
        if conf.dbms in aliases:
            conf.dbms = dbms

            break

def _listTamperingFunctions():
    """
    Lists available tamper functions
    """

    if conf.listTampers:
        infoMsg = "列出可用的tamper脚本\n"
        logger.info(infoMsg)

        for script in sorted(glob.glob(os.path.join(paths.SQLMAP_TAMPER_PATH, "*.py"))):
            content = openFile(script, "rb").read()
            match = re.search(r'(?s)__priority__.+"""(.+)"""', content)
            if match:
                comment = match.group(1).strip()
                dataToStdout("* %s - %s\n" % (setColor(os.path.basename(script), "yellow"), re.sub(r" *\n *", " ", comment.split("\n\n")[0].strip())))

def _setTamperingFunctions():
    """
    Loads tampering functions from given script(s)
    """

    if conf.tamper:
        last_priority = PRIORITY.HIGHEST
        check_priority = True
        resolve_priorities = False
        priorities = []

        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.tamper):
            found = False

            path = safeFilepathEncode(paths.SQLMAP_TAMPER_PATH)
            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                elif os.path.exists(os.path.join(path, script if script.endswith(".py") else "%s.py" % script)):
                    script = os.path.join(path, script if script.endswith(".py") else "%s.py" % script)

                elif not os.path.exists(script):
                    errMsg = "tamper 脚本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "tamper 脚本 '%s' should have an extension '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "选项中提供的字符无效 '--tamper'"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "装载 tamper 模块 '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "确保有一个空文件 '__init__.py' "
                errMsg += "tamper 脚本目录内 '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("无法导入tamper模块 '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            priority = PRIORITY.NORMAL if not hasattr(module, "__priority__") else module.__priority__

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "tamper" and (hasattr(inspect, "signature") and all(_ in inspect.signature(function).parameters for _ in ("payload", "kwargs")) or hasattr(inspect, "getargspec") and inspect.getargspec(function).args and inspect.getargspec(function).keywords == "kwargs"):
                    found = True
                    kb.tamperFunctions.append(function)
                    function.__name__ = module.__name__

                    if check_priority and priority > last_priority:
                        message = "看来您可能混合了 "
                        message += "tamper脚本的顺序. "
                        message += "是否要自动解决此问题？ [Y/n/q] "
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            resolve_priorities = False
                        elif choice == 'Q':
                            raise SqlmapUserQuitException
                        else:
                            resolve_priorities = True

                        check_priority = False

                    priorities.append((priority, function))
                    last_priority = priority

                    break
                elif name == "dependencies":
                    try:
                        function()
                    except Exception as ex:
                        errMsg = "检查tamper模块的依赖 "
                        errMsg += "项时出错 '%s' ('%s')" % (getUnicode(filename[:-3]), getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

            if not found:
                errMsg = "缺少函数 'tamper(payload, **kwargs)' "
                errMsg += "在 tamper 脚本中 '%s'" % script
                raise SqlmapGenericException(errMsg)

        if kb.tamperFunctions and len(kb.tamperFunctions) > 3:
            warnMsg = "使用过多的tamper脚本通常不是 "
            warnMsg += "一个好主意"
            logger.warning(warnMsg)

        if resolve_priorities and priorities:
            priorities.sort(key=functools.cmp_to_key(lambda a, b: cmp(a[0], b[0])), reverse=True)
            kb.tamperFunctions = []

            for _, function in priorities:
                kb.tamperFunctions.append(function)

def _setPreprocessFunctions():
    """
    Loads preprocess function(s) from given script(s)
    """

    if conf.preprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.preprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "预处理脚本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "预处理脚本 '%s' 应具有扩展名 '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "选项中提供的字符无效 '--preprocess'"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "加载预处理模块 '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "确保有一个空文件 '__init__.py' "
                errMsg += "预处理脚本目录内 '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("无法导入预处理模块 '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                try:
                    if name == "preprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("req",)):
                        found = True

                        kb.preprocessFunctions.append(function)
                        function.__name__ = module.__name__

                        break
                except ValueError:  # Note: https://github.com/sqlmapproject/sqlmap/issues/4357
                    pass

            if not found:
                errMsg = "预处理脚本中缺少 "
                errMsg += "函数预处理（req） '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    function(_urllib.request.Request("http://localhost"))
                except:
                    tbMsg = traceback.format_exc()

                    if conf.debug:
                        dataToStdout(tbMsg)

                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef preprocess(req):\n    pass\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "预处理脚本中的函数' "
                    errMsg += "preprep（req） '%s' " % script
                    errMsg += "似乎无效 "
                    errMsg += "(注意：在以下位置查找模板脚本 '%s')" % filename
                    raise SqlmapGenericException(errMsg)

def _setPostprocessFunctions():
    """
    Loads postprocess function(s) from given script(s)
    """

    if conf.postprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.postprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "后处理脚本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "后处理脚本'%s' 应具有扩展名 '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "选项'--postprocess'中提供的字符无效"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "加载后处理模块 '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "确保有一个空文件 '__init__.py' "
                errMsg += "后处理脚本目录内 '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("无法导入后处理模块 '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "postprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("page", "headers", "code")):
                    found = True

                    kb.postprocessFunctions.append(function)
                    function.__name__ = module.__name__

                    break

            if not found:
                errMsg = "缺少函数 'postprocess(page, headers=None, code=None)' "
                errMsg += "在 postprocess 脚本 '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    _, _, _ = function("", {}, None)
                except:
                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef postprocess(page, headers=None, code=None):\n    return page, headers, code\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "函数 'postprocess(page, headers=None, code=None)' "
                    errMsg += "在 postprocess 脚本 '%s' " % script
                    errMsg += "应返回元组 '(page, headers, code)' "
                    errMsg += "(注意：在以下位置查找模板脚本 '%s')" % filename
                    raise SqlmapGenericException(errMsg)

def _setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1

def _setDNSCache():
    """
    Makes a cached version of socket._getaddrinfo to avoid subsequent DNS requests.
    """

    def _getaddrinfo(*args, **kwargs):
        if args in kb.cache.addrinfo:
            return kb.cache.addrinfo[args]

        else:
            kb.cache.addrinfo[args] = socket._getaddrinfo(*args, **kwargs)
            return kb.cache.addrinfo[args]

    if not hasattr(socket, "_getaddrinfo"):
        socket._getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo

def _setSocketPreConnect():
    """
    Makes a pre-connect version of socket.create_connection
    """

    if conf.disablePrecon:
        return

    def _thread():
        while kb.get("threadContinue") and not conf.get("disablePrecon"):
            try:
                for key in socket._ready:
                    if len(socket._ready[key]) < SOCKET_PRE_CONNECT_QUEUE_SIZE:
                        s = socket.create_connection(*key[0], **dict(key[1]))
                        with kb.locks.socket:
                            socket._ready[key].append((s, time.time()))
            except KeyboardInterrupt:
                break
            except:
                pass
            finally:
                time.sleep(0.01)

    def create_connection(*args, **kwargs):
        retVal = None

        key = (tuple(args), frozenset(kwargs.items()))
        with kb.locks.socket:
            if key not in socket._ready:
                socket._ready[key] = []

            while len(socket._ready[key]) > 0:
                candidate, created = socket._ready[key].pop(0)
                if (time.time() - created) < PRECONNECT_CANDIDATE_TIMEOUT:
                    retVal = candidate
                    break
                else:
                    try:
                        candidate.shutdown(socket.SHUT_RDWR)
                        candidate.close()
                    except socket.error:
                        pass

        if not retVal:
            retVal = socket._create_connection(*args, **kwargs)

        return retVal

    if not hasattr(socket, "_create_connection"):
        socket._ready = {}
        socket._create_connection = socket.create_connection
        socket.create_connection = create_connection

        thread = threading.Thread(target=_thread)
        setDaemon(thread)
        thread.start()

def _setHTTPHandlers():
    """
    Check and set the HTTP/SOCKS proxy for all HTTP requests.
    """

    with kb.locks.handlers:
        if conf.proxyList:
            conf.proxy = conf.proxyList[0]
            conf.proxyList = conf.proxyList[1:] + conf.proxyList[:1]

            if len(conf.proxyList) > 1:
                infoMsg = "从提供的代理列表文件加载代理 '%s'" % conf.proxy
                logger.info(infoMsg)

        elif not conf.proxy:
            if conf.hostname in ("localhost", "127.0.0.1") or conf.ignoreProxy:
                proxyHandler.proxies = {}

        if conf.proxy:
            debugMsg = "为所有HTTP请求设置HTTP/SOCKS代理"
            logger.debug(debugMsg)

            try:
                _ = _urllib.parse.urlsplit(conf.proxy)
            except Exception as ex:
                errMsg = "无效的代理地址 '%s' ('%s')" % (conf.proxy, getSafeExString(ex))
                raise SqlmapSyntaxException(errMsg)

            hostnamePort = _.netloc.rsplit(":", 1)

            scheme = _.scheme.upper()
            hostname = hostnamePort[0]
            port = None
            username = None
            password = None

            if len(hostnamePort) == 2:
                try:
                    port = int(hostnamePort[1])
                except:
                    pass  # drops into the next check block

            if not all((scheme, hasattr(PROXY_TYPE, scheme), hostname, port)):
                errMsg = "代理值的格式必须为 '(%s)://address:port'" % "|".join(_[0].lower() for _ in getPublicTypeMembers(PROXY_TYPE))
                raise SqlmapSyntaxException(errMsg)

            if conf.proxyCred:
                _ = re.search(r"\A(.*?):(.*?)\Z", conf.proxyCred)
                if not _:
                    errMsg = "代理身份验证凭据 "
                    errMsg += "值的格式必须为 username:password"
                    raise SqlmapSyntaxException(errMsg)
                else:
                    username = _.group(1)
                    password = _.group(2)

            if scheme in (PROXY_TYPE.SOCKS4, PROXY_TYPE.SOCKS5):
                proxyHandler.proxies = {}

                if scheme == PROXY_TYPE.SOCKS4:
                    warnMsg = "SOCKS4不支持解析（DNS）名称（即导致DNS泄漏）"
                    singleTimeWarnMessage(warnMsg)

                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if scheme == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, hostname, port, username=username, password=password)
                socks.wrapmodule(_http_client)
            else:
                socks.unwrapmodule(_http_client)

                if conf.proxyCred:
                    # Reference: http://stackoverflow.com/questions/34079/how-to-specify-an-authenticated-proxy-for-a-python-http-connection
                    proxyString = "%s@" % conf.proxyCred
                else:
                    proxyString = ""

                proxyString += "%s:%d" % (hostname, port)
                proxyHandler.proxies = {"http": proxyString, "https": proxyString}

            proxyHandler.__init__(proxyHandler.proxies)

        if not proxyHandler.proxies:
            for _ in ("http", "https"):
                if hasattr(proxyHandler, "%s_open" % _):
                    delattr(proxyHandler, "%s_open" % _)

        debugMsg = "创建HTTP请求开启器对象"
        logger.debug(debugMsg)

        handlers = filterNone([multipartPostHandler, proxyHandler if proxyHandler.proxies else None, authHandler, redirectHandler, rangeHandler, chunkedHandler if conf.chunked else None, httpsHandler])

        if not conf.dropSetCookie:
            if not conf.loadCookies:
                conf.cj = _http_cookiejar.CookieJar()
            else:
                conf.cj = _http_cookiejar.MozillaCookieJar()
                resetCookieJar(conf.cj)

            handlers.append(_urllib.request.HTTPCookieProcessor(conf.cj))

        # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
        if conf.keepAlive:
            warnMsg = "持久HTTP连接Keep Alive "
            warnMsg += "由于不兼容而被禁用 "

            if conf.proxy:
                warnMsg += "使用HTTP(S)代理"
                logger.warning(warnMsg)
            elif conf.authType:
                warnMsg += "使用身份验证方法"
                logger.warning(warnMsg)
            else:
                handlers.append(keepAliveHandler)

        opener = _urllib.request.build_opener(*handlers)
        opener.addheaders = []  # Note: clearing default "User-Agent: Python-urllib/X.Y"
        _urllib.request.install_opener(opener)

def _setSafeVisit():
    """
    Check and set the safe visit options.
    """
    if not any((conf.safeUrl, conf.safeReqFile)):
        return

    if conf.safeReqFile:
        checkFile(conf.safeReqFile)

        raw = readCachedFileContent(conf.safeReqFile)
        match = re.search(r"\A([A-Z]+) ([^ ]+) HTTP/[0-9.]+\Z", raw.split('\n')[0].strip())

        if match:
            kb.safeReq.method = match.group(1)
            kb.safeReq.url = match.group(2)
            kb.safeReq.headers = {}

            for line in raw.split('\n')[1:]:
                line = line.strip()
                if line and ':' in line:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    kb.safeReq.headers[key] = value
                    if key.upper() == HTTP_HEADER.HOST.upper():
                        if not value.startswith("http"):
                            scheme = "http"
                            if value.endswith(":443"):
                                scheme = "https"
                            value = "%s://%s" % (scheme, value)
                        kb.safeReq.url = _urllib.parse.urljoin(value, kb.safeReq.url)
                else:
                    break

            post = None

            if '\r\n\r\n' in raw:
                post = raw[raw.find('\r\n\r\n') + 4:]
            elif '\n\n' in raw:
                post = raw[raw.find('\n\n') + 2:]

            if post and post.strip():
                kb.safeReq.post = post
            else:
                kb.safeReq.post = None
        else:
            errMsg = "安全请求文件的格式无效"
            raise SqlmapSyntaxException(errMsg)
    else:
        if not re.search(r"(?i)\Ahttp[s]*://", conf.safeUrl):
            if ":443/" in conf.safeUrl:
                conf.safeUrl = "https://%s" % conf.safeUrl
            else:
                conf.safeUrl = "http://%s" % conf.safeUrl

    if (conf.safeFreq or 0) <= 0:
        errMsg = "使用安全访问功能时，请为安全频率（'---safe-freq'）提供有效值（>0）"
        raise SqlmapSyntaxException(errMsg)

def _setPrefixSuffix():
    if conf.prefix is not None and conf.suffix is not None:
        # Create a custom boundary object for user's supplied prefix
        # and suffix
        boundary = AttribDict()

        boundary.level = 1
        boundary.clause = [0]
        boundary.where = [1, 2, 3]
        boundary.prefix = conf.prefix
        boundary.suffix = conf.suffix

        if " like" in boundary.suffix.lower():
            if "'" in boundary.suffix.lower():
                boundary.ptype = 3
            elif '"' in boundary.suffix.lower():
                boundary.ptype = 5
        elif "'" in boundary.suffix:
            boundary.ptype = 2
        elif '"' in boundary.suffix:
            boundary.ptype = 4
        else:
            boundary.ptype = 1

        # user who provides --prefix/--suffix does not want other boundaries
        # to be tested for
        conf.boundaries = [boundary]

def _setAuthCred():
    """
    Adds authentication credentials (if any) for current target to the password manager
    (used by connection handler)
    """

    if kb.passwordMgr and all(_ is not None for _ in (conf.scheme, conf.hostname, conf.port, conf.authUsername, conf.authPassword)):
        kb.passwordMgr.add_password(None, "%s://%s:%d" % (conf.scheme, conf.hostname, conf.port), conf.authUsername, conf.authPassword)

def _setHTTPAuthentication():
    """
    Check and set the HTTP(s) authentication method (Basic, Digest, Bearer, NTLM or PKI),
    username and password for first three methods, or PEM private key file for
    PKI authentication
    """

    global authHandler

    if not conf.authType and not conf.authCred and not conf.authFile:
        return

    if conf.authFile and not conf.authType:
        conf.authType = AUTH_TYPE.PKI

    elif conf.authType and not conf.authCred and not conf.authFile:
        errMsg = "您指定了HTTP身份验证类型, 但是 "
        errMsg += "未提供凭据"
        raise SqlmapSyntaxException(errMsg)

    elif not conf.authType and conf.authCred:
        errMsg = "您指定了HTTP身份验证凭据, "
        errMsg += "但未提供类型 (e.g. --auth-type=\"basic\")"
        raise SqlmapSyntaxException(errMsg)

    elif (conf.authType or "").lower() not in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST, AUTH_TYPE.BEARER, AUTH_TYPE.NTLM, AUTH_TYPE.PKI):
        errMsg = "HTTP身份验证类型值必须为 "
        errMsg += "Basic, Digest, Bearer, NTLM or PKI"
        raise SqlmapSyntaxException(errMsg)

    if not conf.authFile:
        debugMsg = "设置HTTP身份验证类型和凭据"
        logger.debug(debugMsg)

        authType = conf.authType.lower()

        if authType in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST):
            regExp = "^(.*?):(.*?)$"
            errMsg = "HTTP %s 身份验证凭据 " % authType
            errMsg += "值的格式必须为 'username:password'"
        elif authType == AUTH_TYPE.BEARER:
            conf.httpHeaders.append((HTTP_HEADER.AUTHORIZATION, "Bearer %s" % conf.authCred.strip()))
            return
        elif authType == AUTH_TYPE.NTLM:
            regExp = "^(.*\\\\.*):(.*?)$"
            errMsg = "HTTP NTLM身份验证凭据值的 "
            errMsg += "格式必须为 'DOMAIN\\username:password'"
        elif authType == AUTH_TYPE.PKI:
            errMsg = "HTTP PKI身份验证 "
            errMsg += "需要使用选项 `--auth-pki`"
            raise SqlmapSyntaxException(errMsg)

        aCredRegExp = re.search(regExp, conf.authCred)

        if not aCredRegExp:
            raise SqlmapSyntaxException(errMsg)

        conf.authUsername = aCredRegExp.group(1)
        conf.authPassword = aCredRegExp.group(2)

        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

        _setAuthCred()

        if authType == AUTH_TYPE.BASIC:
            authHandler = SmartHTTPBasicAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.DIGEST:
            authHandler = _urllib.request.HTTPDigestAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.NTLM:
            try:
                from ntlm import HTTPNtlmAuthHandler
            except ImportError:
                errMsg = "sqlmap需要Python NTLM第三方库 "
                errMsg += "以便通过NTLM进行身份验证.从下载 "
                errMsg += "'https://github.com/mullender/python-ntlm'"
                raise SqlmapMissingDependence(errMsg)

            authHandler = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(kb.passwordMgr)
    else:
        debugMsg = "设置HTTP(S)身份验证PEM私钥"
        logger.debug(debugMsg)

        _ = safeExpandUser(conf.authFile)
        checkFile(_)
        authHandler = HTTPSPKIAuthHandler(_)

def _setHTTPExtraHeaders():
    if conf.headers:
        debugMsg = "设置额外的HTTP标头"
        logger.debug(debugMsg)

        conf.headers = conf.headers.split("\n") if "\n" in conf.headers else conf.headers.split("\\n")

        for headerValue in conf.headers:
            if not headerValue.strip():
                continue

            if headerValue.count(':') >= 1:
                header, value = (_.lstrip() for _ in headerValue.split(":", 1))

                if header and value:
                    conf.httpHeaders.append((header, value))
            elif headerValue.startswith('@'):
                checkFile(headerValue[1:])
                kb.headersFile = headerValue[1:]
            else:
                errMsg = "无效的标头值: %s. 有效的标头格式为'name:value'" % repr(headerValue).lstrip('u')
                raise SqlmapSyntaxException(errMsg)

    elif not conf.requestFile and len(conf.httpHeaders or []) < 2:
        if conf.encoding:
            conf.httpHeaders.append((HTTP_HEADER.ACCEPT_CHARSET, "%s;q=0.7,*;q=0.1" % conf.encoding))

        # Invalidating any caching mechanism in between
        # Reference: http://stackoverflow.com/a/1383359
        conf.httpHeaders.append((HTTP_HEADER.CACHE_CONTROL, "no-cache"))

def _setHTTPUserAgent():
    """
    Set the HTTP User-Agent header.
    Depending on the user options it can be:

        * The default sqlmap string
        * A default value read as user option
        * A random value read from a list of User-Agent headers from a
          file choosed as user option
    """

    debugMsg = "setting the HTTP User-Agent header"
    logger.debug(debugMsg)

    if conf.mobile:
        if conf.randomAgent:
            _ = random.sample([_[1] for _ in getPublicTypeMembers(MOBILES, True)], 1)[0]
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, _))
        else:
            message = "你希望sqlmap模仿哪个智能手机 "
            message += "通过HTTP User-Agent 头?\n"
            items = sorted(getPublicTypeMembers(MOBILES, True))

            for count in xrange(len(items)):
                item = items[count]
                message += "[%d] %s%s\n" % (count + 1, item[0], " (default)" if item == MOBILES.IPHONE else "")

            test = readInput(message.rstrip('\n'), default=items.index(MOBILES.IPHONE) + 1)

            try:
                item = items[int(test) - 1]
            except:
                item = MOBILES.IPHONE

            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, item[1]))

    elif conf.agent:
        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, conf.agent))

    elif not conf.randomAgent:
        _ = True

        for header, _ in conf.httpHeaders:
            if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                _ = False
                break

        if _:
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, DEFAULT_USER_AGENT))

    else:
        userAgent = fetchRandomAgent()

        infoMsg = "已获取随机HTTP User-Agent 标头值 '%s' from " % userAgent
        infoMsg += "file '%s'" % paths.USER_AGENTS
        logger.info(infoMsg)

        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, userAgent))

def _setHTTPReferer():
    """
    Set the HTTP Referer
    """

    if conf.referer:
        debugMsg = "设置HTTP Refer标头"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.referer))

def _setHTTPHost():
    """
    Set the HTTP Host
    """

    if conf.host:
        debugMsg = "设置HTTP主机标头"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.HOST, conf.host))

def _setHTTPCookies():
    """
    Set the HTTP Cookie header
    """

    if conf.cookie:
        debugMsg = "设置HTTP Cookie标头"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.COOKIE, conf.cookie))

def _setHostname():
    """
    Set value conf.hostname
    """

    if conf.url:
        try:
            conf.hostname = _urllib.parse.urlsplit(conf.url).netloc.split(':')[0]
        except ValueError as ex:
            errMsg = "分析URL时 "
            errMsg += "出现问题 '%s' ('%s')" % (conf.url, getSafeExString(ex))
            raise SqlmapDataException(errMsg)

def _setHTTPTimeout():
    """
    Set the HTTP timeout
    """

    if conf.timeout:
        debugMsg = "设置HTTP超时"
        logger.debug(debugMsg)

        conf.timeout = float(conf.timeout)

        if conf.timeout < 3.0:
            warnMsg = "最小HTTP超时为3秒 ,sqlmap "
            warnMsg += "将重置它"
            logger.warning(warnMsg)

            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    try:
        socket.setdefaulttimeout(conf.timeout)
    except OverflowError as ex:
        raise SqlmapValueException("用于选项的值无效 '--timeout' ('%s')" % getSafeExString(ex))

def _checkDependencies():
    """
    Checks for missing dependencies.
    """

    if conf.dependencies:
        checkDependencies()

def _createHomeDirectories():
    """
    Creates directories inside sqlmap's home directory
    """

    if conf.get("purge"):
        return

    for context in ("output", "history"):
        directory = paths["SQLMAP_%s_PATH" % getUnicode(context).upper()]   # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4363
        try:
            if not os.path.isdir(directory):
                os.makedirs(directory)

            _ = os.path.join(directory, randomStr())
            open(_, "w+b").close()
            os.remove(_)

            if conf.get("outputDir") and context == "output":
                warnMsg = "使用 '%s' 作为 %s 目录" % (directory, context)
                logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmap%s" % context)
            warnMsg = "无法 %s %s 目录 " % ("create" if not os.path.isdir(directory) else "write to the", context)
            warnMsg += "'%s' (%s). " % (directory, getUnicode(ex))
            warnMsg += "改用临时目录 '%s'" % getUnicode(tempDir)
            logger.warning(warnMsg)

            paths["SQLMAP_%s_PATH" % context.upper()] = tempDir

def _pympTempLeakPatch(tempDir):  # Cross-referenced function
    raise NotImplementedError

def _createTemporaryDirectory():
    """
    Creates temporary directory for this run.
    """

    if conf.tmpDir:
        try:
            if not os.path.isdir(conf.tmpDir):
                os.makedirs(conf.tmpDir)

            _ = os.path.join(conf.tmpDir, randomStr())

            open(_, "w+b").close()
            os.remove(_)

            tempfile.tempdir = conf.tmpDir

            warnMsg = "使用 '%s' 作为临时目录" % conf.tmpDir
            logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            errMsg = "访问时出现问题 "
            errMsg += "临时目录位置 ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)
    else:
        try:
            if not os.path.isdir(tempfile.gettempdir()):
                os.makedirs(tempfile.gettempdir())
        except Exception as ex:
            warnMsg = "访问系统的临时 "
            warnMsg += "目录位置时出现问题 ('%s'). 请 " % getSafeExString(ex)
            warnMsg += "确保有足够的磁盘空间. 如果问题仍然存在, "
            warnMsg += "尝试将环境变量'TEMP'设置为某个位置 "
            warnMsg += "可由当前用户写入"
            logger.warning(warnMsg)

    if "sqlmap" not in (tempfile.tempdir or "") or conf.tmpDir and tempfile.tempdir == conf.tmpDir:
        try:
            tempfile.tempdir = tempfile.mkdtemp(prefix="sqlmap", suffix=str(os.getpid()))
        except:
            tempfile.tempdir = os.path.join(paths.SQLMAP_HOME_PATH, "tmp", "sqlmap%s%d" % (randomStr(6), os.getpid()))

    kb.tempDir = tempfile.tempdir

    if not os.path.isdir(tempfile.tempdir):
        try:
            os.makedirs(tempfile.tempdir)
        except Exception as ex:
            errMsg = "设置时出现问题 "
            errMsg += "临时目录位置 ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)

    if six.PY3:
        _pympTempLeakPatch(kb.tempDir)

def _cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    if conf.encoding:
        try:
            codecs.lookup(conf.encoding)
        except LookupError:
            errMsg = "未知编码 '%s'" % conf.encoding
            raise SqlmapValueException(errMsg)

    debugMsg = "清理配置参数"
    logger.debug(debugMsg)

    width = getConsoleWidth()

    if conf.eta:
        conf.progressWidth = width - 26
    else:
        conf.progressWidth = width - 46

    for key, value in conf.items():
        if value and any(key.endswith(_) for _ in ("Path", "File", "Dir")):
            if isinstance(value, str):
                conf[key] = safeExpandUser(value)

    if conf.testParameter:
        conf.testParameter = urldecode(conf.testParameter)
        conf.testParameter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.testParameter)]
    else:
        conf.testParameter = []

    if conf.ignoreCode:
        if conf.ignoreCode == IGNORE_CODE_WILDCARD:
            conf.ignoreCode = xrange(0, 1000)
        else:
            try:
                conf.ignoreCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.ignoreCode)]
            except ValueError:
                errMsg = "选项'--ignore-code'应包含整数值列表或通配符值 '%s'" % IGNORE_CODE_WILDCARD
                raise SqlmapSyntaxException(errMsg)
    else:
        conf.ignoreCode = []

    if conf.paramFilter:
        conf.paramFilter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.paramFilter.upper())]
    else:
        conf.paramFilter = []

    if conf.base64Parameter:
        conf.base64Parameter = urldecode(conf.base64Parameter)
        conf.base64Parameter = conf.base64Parameter.strip()
        conf.base64Parameter = re.split(PARAMETER_SPLITTING_REGEX, conf.base64Parameter)
    else:
        conf.base64Parameter = []

    if conf.agent:
        conf.agent = re.sub(r"[\r\n]", "", conf.agent)

    if conf.user:
        conf.user = conf.user.replace(" ", "")

    if conf.rParam:
        if all(_ in conf.rParam for _ in ('=', ',')):
            original = conf.rParam
            conf.rParam = []
            for part in original.split(';'):
                if '=' in part:
                    left, right = part.split('=', 1)
                    conf.rParam.append(left)
                    kb.randomPool[left] = filterNone(_.strip() for _ in right.split(','))
                else:
                    conf.rParam.append(part)
        else:
            conf.rParam = conf.rParam.replace(" ", "")
            conf.rParam = re.split(PARAMETER_SPLITTING_REGEX, conf.rParam)
    else:
        conf.rParam = []

    if conf.paramDel:
        conf.paramDel = decodeStringEscape(conf.paramDel)

    if conf.skip:
        conf.skip = conf.skip.replace(" ", "")
        conf.skip = re.split(PARAMETER_SPLITTING_REGEX, conf.skip)
    else:
        conf.skip = []

    if conf.cookie:
        conf.cookie = re.sub(r"[\r\n]", "", conf.cookie)

    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.url:
        conf.url = conf.url.strip().lstrip('/')
        if not re.search(r"\A\w+://", conf.url):
            conf.url = "http://%s" % conf.url

    if conf.fileRead:
        conf.fileRead = ntToPosixSlashes(normalizePath(conf.fileRead))

    if conf.fileWrite:
        conf.fileWrite = ntToPosixSlashes(normalizePath(conf.fileWrite))

    if conf.fileDest:
        conf.fileDest = ntToPosixSlashes(normalizePath(conf.fileDest))

    if conf.msfPath:
        conf.msfPath = ntToPosixSlashes(normalizePath(conf.msfPath))

    if conf.tmpPath:
        conf.tmpPath = ntToPosixSlashes(normalizePath(conf.tmpPath))

    if any((conf.googleDork, conf.logFile, conf.bulkFile, conf.forms, conf.crawlDepth, conf.stdinPipe)):
        conf.multipleTargets = True

    if conf.optimize:
        setOptimize()

    if conf.os:
        conf.os = conf.os.capitalize()

    if conf.forceDbms:
        conf.dbms = conf.forceDbms

    if conf.dbms:
        kb.dbmsFilter = []
        for _ in conf.dbms.split(','):
            for dbms, aliases in DBMS_ALIASES:
                if _.strip().lower() in aliases:
                    kb.dbmsFilter.append(dbms)
                    conf.dbms = dbms if conf.dbms and ',' not in conf.dbms else None
                    break

    if conf.testFilter:
        conf.testFilter = conf.testFilter.strip('*+')
        conf.testFilter = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testFilter)

        try:
            re.compile(conf.testFilter)
        except re.error:
            conf.testFilter = re.escape(conf.testFilter)

    if conf.csrfToken:
        original = conf.csrfToken
        try:
            re.compile(conf.csrfToken)

            if re.escape(conf.csrfToken) != conf.csrfToken:
                message = "为选项'--csrf-token'提供的值是正则表达式吗？ [y/N] "
                if not readInput(message, default='N', boolean=True):
                    conf.csrfToken = re.escape(conf.csrfToken)
        except re.error:
            conf.csrfToken = re.escape(conf.csrfToken)
        finally:
            class _(six.text_type):
                pass
            conf.csrfToken = _(conf.csrfToken)
            conf.csrfToken._original = original

    if conf.testSkip:
        conf.testSkip = conf.testSkip.strip('*+')
        conf.testSkip = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testSkip)

        try:
            re.compile(conf.testSkip)
        except re.error:
            conf.testSkip = re.escape(conf.testSkip)

    if "timeSec" not in kb.explicitSettings:
        if conf.tor:
            conf.timeSec = 2 * conf.timeSec
            kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

            warnMsg = "增加的默认值 "
            warnMsg += "选项'--time-sec'设置为 %d 因为 " % conf.timeSec
            warnMsg += "提供了开关'--tor'"
            logger.warning(warnMsg)
    else:
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

    if conf.retries:
        conf.retries = min(conf.retries, MAX_CONNECT_RETRIES)

    if conf.url:
        match = re.search(r"\A(\w+://)?([^/@?]+)@", conf.url)
        if match:
            credentials = match.group(2)
            conf.url = conf.url.replace("%s@" % credentials, "", 1)

            conf.authType = AUTH_TYPE.BASIC
            conf.authCred = credentials if ':' in credentials else "%s:" % credentials

    if conf.code:
        conf.code = int(conf.code)

    if conf.csvDel:
        conf.csvDel = decodeStringEscape(conf.csvDel)

    if conf.torPort and hasattr(conf.torPort, "isdigit") and conf.torPort.isdigit():
        conf.torPort = int(conf.torPort)

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.outputDir:
        paths.SQLMAP_OUTPUT_PATH = os.path.realpath(os.path.expanduser(conf.outputDir))
        setPaths(paths.SQLMAP_ROOT_PATH)

    if conf.string:
        conf.string = decodeStringEscape(conf.string)

    if conf.getAll:
        for _ in WIZARD.ALL:
            conf.__setitem__(_, True)

    if conf.noCast:
        DUMP_REPLACEMENTS.clear()

    if conf.dumpFormat:
        conf.dumpFormat = conf.dumpFormat.upper()

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.col:
        conf.col = re.sub(r"\s*,\s*", ',', conf.col)

    if conf.exclude:
        regex = False
        original = conf.exclude

        if any(_ in conf.exclude for _ in ('+', '*')):
            try:
                re.compile(conf.exclude)
            except re.error:
                pass
            else:
                regex = True

        if not regex:
            conf.exclude = re.sub(r"\s*,\s*", ',', conf.exclude)
            conf.exclude = r"\A%s\Z" % '|'.join(re.escape(_) for _ in conf.exclude.split(','))
        else:
            conf.exclude = re.sub(r"(\w+)\$", r"\g<1>\$", conf.exclude)

        class _(six.text_type):
            pass

        conf.exclude = _(conf.exclude)
        conf.exclude._original = original

    if conf.binaryFields:
        conf.binaryFields = conf.binaryFields.replace(" ", "")
        conf.binaryFields = re.split(PARAMETER_SPLITTING_REGEX, conf.binaryFields)

    envProxy = max(os.environ.get(_, "") for _ in PROXY_ENVIRONMENT_VARIABLES)
    if re.search(r"\A(https?|socks[45])://.+:\d+\Z", envProxy) and conf.proxy is None:
        debugMsg = "使用环境代理 '%s'" % envProxy
        logger.debug(debugMsg)

        conf.proxy = envProxy

    if any((conf.proxy, conf.proxyFile, conf.tor)):
        conf.disablePrecon = True

    if conf.dummy:
        conf.batch = True

    threadData = getCurrentThreadData()
    threadData.reset()

def _cleanupEnvironment():
    """
    Cleanup environment (e.g. from leftovers after --shell).
    """

    if issubclass(_http_client.socket.socket, socks.socksocket):
        socks.unwrapmodule(_http_client)

    if hasattr(socket, "_ready"):
        socket._ready.clear()

def _purge():
    """
    Safely removes (purges) sqlmap data directory.
    """

    if conf.purge:
        purge(paths.SQLMAP_HOME_PATH)

def _setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = "初始化配置"
    logger.debug(debugMsg)

    conf.authUsername = None
    conf.authPassword = None
    conf.boundaries = []
    conf.cj = None
    conf.dbmsConnector = None
    conf.dbmsHandler = None
    conf.dnsServer = None
    conf.dumpPath = None
    conf.hashDB = None
    conf.hashDBFile = None
    conf.httpCollector = None
    conf.httpHeaders = []
    conf.hostname = None
    conf.ipv6 = False
    conf.multipleTargets = False
    conf.outputPath = None
    conf.paramDict = {}
    conf.parameters = {}
    conf.path = None
    conf.port = None
    conf.proxyList = None
    conf.resultsFP = None
    conf.scheme = None
    conf.tests = []
    conf.trafficFP = None
    conf.HARCollectorFactory = None
    conf.fileWriteType = None

def _setKnowledgeBaseAttributes(flushAll=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = "initializing the knowledge base"
    logger.debug(debugMsg)

    kb.absFilePaths = set()
    kb.adjustTimeDelay = None
    kb.alerted = False
    kb.aliasName = randomStr()
    kb.alwaysRefresh = None
    kb.arch = None
    kb.authHeader = None
    kb.bannerFp = AttribDict()
    kb.base64Originals = {}
    kb.binaryField = False
    kb.browserVerification = None

    kb.brute = AttribDict({"tables": [], "columns": []})
    kb.bruteMode = False

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = {}
    kb.cache.comparison = {}
    kb.cache.encoding = {}
    kb.cache.alphaBoundaries = None
    kb.cache.hashRegex = None
    kb.cache.intBoundaries = None
    kb.cache.parsedDbms = {}
    kb.cache.regex = {}
    kb.cache.stdev = {}

    kb.captchaDetected = None

    kb.chars = AttribDict()
    kb.chars.delimiter = randomStr(length=6, lowercase=True)
    kb.chars.start = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.stop = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.at, kb.chars.space, kb.chars.dollar, kb.chars.hash_ = ("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, _, KB_CHARS_BOUNDARY_CHAR) for _ in randomStr(length=4, lowercase=True))

    kb.choices = AttribDict(keycheck=False)
    kb.codePage = None
    kb.commonOutputs = None
    kb.connErrorCounter = 0
    kb.copyExecTest = None
    kb.counters = {}
    kb.customInjectionMark = CUSTOM_INJECTION_MARK_CHAR
    kb.data = AttribDict()
    kb.dataOutputFlag = False

    # Active back-end DBMS fingerprint
    kb.dbms = None
    kb.dbmsFilter = []
    kb.dbmsVersion = [UNKNOWN_DBMS_VERSION]

    kb.delayCandidates = TIME_DELAY_CANDIDATES * [0]
    kb.dep = None
    kb.disableHtmlDecoding = False
    kb.disableShiftTable = False
    kb.dnsMode = False
    kb.dnsTest = None
    kb.docRoot = None
    kb.droppingRequests = False
    kb.dumpColumns = None
    kb.dumpTable = None
    kb.dumpKeyboardInterrupt = False
    kb.dynamicMarkings = []
    kb.dynamicParameter = False
    kb.endDetection = False
    kb.explicitSettings = set()
    kb.extendTests = None
    kb.errorChunkLength = None
    kb.errorIsNone = True
    kb.falsePositives = []
    kb.fileReadMode = False
    kb.fingerprinted = False
    kb.followSitemapRecursion = None
    kb.forcedDbms = None
    kb.forcePartialUnion = False
    kb.forceThreads = None
    kb.forceWhere = None
    kb.forkNote = None
    kb.futileUnion = None
    kb.fuzzUnionTest = None
    kb.heavilyDynamic = False
    kb.headersFile = None
    kb.headersFp = {}
    kb.heuristicDbms = None
    kb.heuristicExtendedDbms = None
    kb.heuristicMode = False
    kb.heuristicPage = False
    kb.heuristicTest = None
    kb.hintValue = ""
    kb.htmlFp = []
    kb.httpErrorCodes = {}
    kb.inferenceMode = False
    kb.ignoreCasted = None
    kb.ignoreNotFound = False
    kb.ignoreTimeout = False
    kb.identifiedWafs = set()
    kb.injection = InjectionDict()
    kb.injections = []
    kb.jsonAggMode = False
    kb.laggingChecked = False
    kb.lastParserStatus = None

    kb.locks = AttribDict()
    for _ in ("cache", "connError", "count", "handlers", "hint", "identYwaf", "index", "io", "limit", "liveCookies", "log", "socket", "redirect", "request", "value"):
        kb.locks[_] = threading.Lock()

    kb.matchRatio = None
    kb.maxConnectionsFlag = False
    kb.mergeCookies = None
    kb.multiThreadMode = False
    kb.multipleCtrlC = False
    kb.negativeLogic = False
    kb.nchar = True
    kb.nullConnection = None
    kb.oldMsf = None
    kb.orderByColumns = None
    kb.originalCode = None
    kb.originalPage = None
    kb.originalPageTime = None
    kb.originalTimeDelay = None
    kb.originalUrls = dict()

    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing
    kb.os = None
    kb.osVersion = None
    kb.osSP = None

    kb.pageCompress = True
    kb.pageTemplate = None
    kb.pageTemplates = dict()
    kb.pageEncoding = DEFAULT_PAGE_ENCODING
    kb.pageStable = None
    kb.partRun = None
    kb.permissionFlag = False
    kb.place = None
    kb.postHint = None
    kb.postSpaceToPlus = False
    kb.postUrlEncode = True
    kb.prependFlag = False
    kb.processResponseCounter = 0
    kb.previousMethod = None
    kb.processUserMarks = None
    kb.proxyAuthHeader = None
    kb.queryCounter = 0
    kb.randomPool = {}
    kb.reflectiveMechanism = True
    kb.reflectiveCounters = {REFLECTIVE_COUNTER.MISS: 0, REFLECTIVE_COUNTER.HIT: 0}
    kb.requestCounter = 0
    kb.resendPostOnRedirect = None
    kb.resolutionDbms = None
    kb.responseTimes = {}
    kb.responseTimeMode = None
    kb.responseTimePayload = None
    kb.resumeValues = True
    kb.safeCharEncode = False
    kb.safeReq = AttribDict()
    kb.secondReq = None
    kb.serverHeader = None
    kb.singleLogFlags = set()
    kb.skipSeqMatcher = False
    kb.smokeMode = False
    kb.reduceTests = None
    kb.sslSuccess = False
    kb.stickyDBMS = False
    kb.suppressResumeInfo = False
    kb.tableFrom = None
    kb.technique = None
    kb.tempDir = None
    kb.testMode = False
    kb.testOnlyCustom = False
    kb.testQueryCount = 0
    kb.testType = None
    kb.threadContinue = True
    kb.threadException = False
    kb.uChar = NULL
    kb.udfFail = False
    kb.unionDuplicates = False
    kb.unionTemplate = None
    kb.webSocketRecvCount = None
    kb.wizardMode = False
    kb.xpCmdshellAvailable = False

    if flushAll:
        kb.checkSitemap = None
        kb.headerPaths = {}
        kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))
        kb.lastCtrlCTime = None
        kb.normalizeCrawlingChoice = None
        kb.passwordMgr = None
        kb.postprocessFunctions = []
        kb.preprocessFunctions = []
        kb.skipVulnHost = None
        kb.storeCrawlingChoice = None
        kb.tamperFunctions = []
        kb.targets = OrderedSet()
        kb.testedParams = set()
        kb.userAgents = None
        kb.vainRun = True
        kb.vulnHosts = set()
        kb.wafFunctions = []
        kb.wordlists = None

def _useWizardInterface():
    """
    Presents simple wizard interface for beginner users
    """

    if not conf.wizard:
        return

    logger.info("启动向导界面")

    while not conf.url:
        message = "请输入完整的目标URL (-u): "
        conf.url = readInput(message, default=None, checkBatch=False)

    message = "%s 数据 (--data) [输入表示无]: " % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
    conf.data = readInput(message, default=None)

    if not (any('=' in _ for _ in (conf.url, conf.data)) or '*' in conf.url):
        warnMsg = "未找到用于测试的GET和/或 %s 参数 " % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
        warnMsg += "(例子 GET 参数 'id' in 'http://www.site.com/vuln.php?id=1'). "
        if not conf.crawlDepth and not conf.forms:
            warnMsg += "将搜索表单"
            conf.forms = True
        logger.warning(warnMsg)

    choice = None

    while choice is None or choice not in ("", "1", "2", "3"):
        message = "注射难度 (--level/--risk). 请选择:\n"
        message += "[1] 正常 (默认)\n[2] 中等的\n[3] 坚固的"
        choice = readInput(message, default='1')

        if choice == '2':
            conf.risk = 2
            conf.level = 3
        elif choice == '3':
            conf.risk = 3
            conf.level = 5
        else:
            conf.risk = 1
            conf.level = 1

    if not conf.getAll:
        choice = None

        while choice is None or choice not in ("", "1", "2", "3"):
            message = "枚举 (--banner/--current-user/etc). 请选择:\n"
            message += "[1] 基本 (默认)\n[2] 中等的\n[3] 全部"
            choice = readInput(message, default='1')

            if choice == '2':
                options = WIZARD.INTERMEDIATE
            elif choice == '3':
                options = WIZARD.ALL
            else:
                options = WIZARD.BASIC

            for _ in options:
                conf.__setitem__(_, True)

    logger.debug("禁用 sqlmap.. 它会为你带来魔力")
    conf.verbose = 0

    conf.batch = True
    conf.threads = 4

    dataToStdout("\nsqlmap正在运行, 请稍候..\n\n")

    kb.wizardMode = True

def _saveConfig():
    """
    Saves the command line options to a sqlmap configuration INI file
    Format.
    """

    if not conf.saveConfig:
        return

    debugMsg = "将命令行选项保存到sqlmap配置INI文件"
    logger.debug(debugMsg)

    saveConfig(conf, conf.saveConfig)

    infoMsg = "将命令行选项保存到配置文件 '%s'" % conf.saveConfig
    logger.info(infoMsg)

def setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.ERROR)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 2 and conf.eta:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(CUSTOM_LOGGING.PAYLOAD)
    elif conf.verbose == 4:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_OUT)
    elif conf.verbose >= 5:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_IN)

def _normalizeOptions(inputOptions):
    """
    Sets proper option types
    """

    types_ = {}
    for group in optDict.keys():
        types_.update(optDict[group])

    for key in inputOptions:
        if key in types_:
            value = inputOptions[key]
            if value is None:
                continue

            type_ = types_[key]
            if type_ and isinstance(type_, tuple):
                type_ = type_[0]

            if type_ == OPTION_TYPE.BOOLEAN:
                try:
                    value = bool(value)
                except (TypeError, ValueError):
                    value = False
            elif type_ == OPTION_TYPE.INTEGER:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = 0
            elif type_ == OPTION_TYPE.FLOAT:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    value = 0.0

            inputOptions[key] = value

def _mergeOptions(inputOptions, overrideOptions):
    """
    Merge command line options with configuration file and default options.

    @param inputOptions: optparse object with command line options.
    @type inputOptions: C{instance}
    """

    if inputOptions.configFile:
        configFileParser(inputOptions.configFile)

    if hasattr(inputOptions, "items"):
        inputOptionsItems = inputOptions.items()
    else:
        inputOptionsItems = inputOptions.__dict__.items()

    for key, value in inputOptionsItems:
        if key not in conf or value not in (None, False) or overrideOptions:
            conf[key] = value

    if not conf.api:
        for key, value in conf.items():
            if value is not None:
                kb.explicitSettings.add(key)

    for key, value in defaults.items():
        if hasattr(conf, key) and conf[key] is None:
            conf[key] = value

            if conf.unstable:
                if key in ("timeSec", "retries", "timeout"):
                    conf[key] *= 2

    if conf.unstable:
        conf.forcePartial = True

    lut = {}
    for group in optDict.keys():
        lut.update((_.upper(), _) for _ in optDict[group])

    envOptions = {}
    for key, value in os.environ.items():
        if key.upper().startswith(SQLMAP_ENVIRONMENT_PREFIX):
            _ = key[len(SQLMAP_ENVIRONMENT_PREFIX):].upper()
            if _ in lut:
                envOptions[lut[_]] = value

    if envOptions:
        _normalizeOptions(envOptions)
        for key, value in envOptions.items():
            conf[key] = value

    mergedOptions.update(conf)

def _setTrafficOutputFP():
    if conf.trafficFile:
        infoMsg = "用于记录HTTP流量的设置文件"
        logger.info(infoMsg)

        conf.trafficFP = openFile(conf.trafficFile, "w+")

def _setupHTTPCollector():
    if not conf.harFile:
        return

    conf.httpCollector = HTTPCollectorFactory(conf.harFile).create()

def _setDNSServer():
    if not conf.dnsDomain:
        return

    infoMsg = "设置DNS服务器实例"
    logger.info(infoMsg)

    isAdmin = runningAsAdmin()

    if isAdmin:
        try:
            conf.dnsServer = DNSServer()
            conf.dnsServer.run()
        except socket.error as ex:
            errMsg = "设置时出错 "
            errMsg += "DNS服务器实例 ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)
    else:
        errMsg = "如果要执行DNS数据过滤攻击, "
        errMsg += "您需要以管理员身份运行sqlmap, "
        errMsg += "因为它需要在特权UDP端口 "
        errMsg += "53上侦听传入的地址解析尝试"
        raise SqlmapMissingPrivileges(errMsg)

def _setProxyList():
    if not conf.proxyFile:
        return

    conf.proxyList = []
    for match in re.finditer(r"(?i)((http[^:]*|socks[^:]*)://)?([\w\-.]+):(\d+)", readCachedFileContent(conf.proxyFile)):
        _, type_, address, port = match.groups()
        conf.proxyList.append("%s://%s:%s" % (type_ or "http", address, port))

def _setTorProxySettings():
    if not conf.tor:
        return

    if conf.torType == PROXY_TYPE.HTTP:
        _setTorHttpProxySettings()
    else:
        _setTorSocksProxySettings()

def _setTorHttpProxySettings():
    infoMsg = "设置Tor HTTP代理设置"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_HTTP_PORTS if not conf.torPort else (conf.torPort,))

    if port:
        conf.proxy = "http://%s:%d" % (LOCALHOST, port)
    else:
        errMsg = "无法与Tor HTTP代理建立连接. "
        errMsg += "请确保已安装并安装Tor（捆绑包） "
        errMsg += "这样您就可以成功地使用开关 '--tor' "
        raise SqlmapConnectionException(errMsg)

    if not conf.checkTor:
        warnMsg = "在访问tor匿名网络时, "
        warnMsg += "由于各种'捆绑包'的默认设置 "
        warnMsg += "存在已知问题,请自行 "
        warnMsg += "使用开关'--check tor' "
        warnMsg += "(例如 Vidalia)"
        logger.warning(warnMsg)

def _setTorSocksProxySettings():
    infoMsg = "设置Tor SOCKS代理设置"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_SOCKS_PORTS if not conf.torPort else (conf.torPort,))

    if not port:
        errMsg = "无法与Tor SOCKS代理建立连接. "
        errMsg += "请确保已安装并设置Tor服务,"
        errMsg += "以便能够成功使用开关'--Tor' "
        raise SqlmapConnectionException(errMsg)

    # SOCKS5 to prevent DNS leaks (http://en.wikipedia.org/wiki/Tor_%28anonymity_network%29)
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if conf.torType == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, LOCALHOST, port)
    socks.wrapmodule(_http_client)

def _setHttpChunked():
    if conf.chunked and conf.data:
        if hasattr(_http_client.HTTPConnection, "_set_content_length"):
            _http_client.HTTPConnection._set_content_length = lambda self, *args, **kwargs: None
        else:
            def putheader(self, header, *values):
                if header != HTTP_HEADER.CONTENT_LENGTH:
                    self._putheader(header, *values)

            if not hasattr(_http_client.HTTPConnection, "_putheader"):
                _http_client.HTTPConnection._putheader = _http_client.HTTPConnection.putheader

            _http_client.HTTPConnection.putheader = putheader

def _checkWebSocket():
    if conf.url and (conf.url.startswith("ws:/") or conf.url.startswith("wss:/")):
        try:
            from websocket import ABNF
        except ImportError:
            errMsg = "sqlmap需要第三方模块 'websocket-client' "
            errMsg += "为了使用WebSocket功能"
            raise SqlmapMissingDependence(errMsg)

def _checkTor():
    if not conf.checkTor:
        return

    infoMsg = "检查Tor连接"
    logger.info(infoMsg)

    try:
        page, _, _ = Request.getPage(url="https://check.torproject.org/", raise404=False)
    except SqlmapConnectionException:
        page = None

    if not page or "Congratulations" not in page:
        errMsg = "看来Tor没有正确设置。请尝试使用选项'--tor-type'和/或'--tor-port'"
        raise SqlmapConnectionException(errMsg)
    else:
        infoMsg = "正确使用Tor"
        logger.info(infoMsg)

def _basicOptionValidation():
    if conf.limitStart is not None and not (isinstance(conf.limitStart, int) and conf.limitStart > 0):
        errMsg = "选项'--start'（limitStart）的值必须是大于零（>0）的整数值"
        raise SqlmapSyntaxException(errMsg)

    if conf.limitStop is not None and not (isinstance(conf.limitStop, int) and conf.limitStop > 0):
        errMsg = "选项'--stop'（limitStop）的值必须是大于零（>0）的整数值"
        raise SqlmapSyntaxException(errMsg)

    if conf.level is not None and not (isinstance(conf.level, int) and conf.level >= 1 and conf.level <= 5):
        errMsg = "选项'--level'的值必须是范围[1，5]中的整数值"
        raise SqlmapSyntaxException(errMsg)

    if conf.risk is not None and not (isinstance(conf.risk, int) and conf.risk >= 1 and conf.risk <= 3):
        errMsg = "选项'--risk'的值必须是范围[1，3]中的整数值"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.limitStart, int) and conf.limitStart > 0 and \
       isinstance(conf.limitStop, int) and conf.limitStop < conf.limitStart:
        warnMsg = "选项'--start'（limitStart）的使用大于--stop（limitStop）选项的值被认为是不稳定的"
        logger.warning(warnMsg)

    if isinstance(conf.firstChar, int) and conf.firstChar > 0 and \
       isinstance(conf.lastChar, int) and conf.lastChar < conf.firstChar:
        errMsg = "选项'--first'（firstChar）的值必须小于或等于--last（lastChar）选项的值"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFile and not any((conf.randomAgent, conf.mobile, conf.agent, conf.requestFile)):
        warnMsg = "强烈建议在使用选项'--proxy-file'时 "
        warnMsg += "使用开关''--random-agent'"
        logger.warning(warnMsg)

    if conf.textOnly and conf.nullConnection:
        errMsg = "开关'--text-only'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.base64Parameter and conf.tamper:
        errMsg = "选项'--base64'与选项'--tamper'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.eta and conf.verbose > defaults.verbose:
        errMsg = "开关'--eta'与选项'-v'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.secondUrl and conf.secondReq:
        errMsg = "选项'--second-url'与选项'--second-req'不兼容）"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.url:
        errMsg = "选项'-d'与选项'-u'（'--url'）不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.dbms:
        errMsg = "选项'-d'与选项'--dbms'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.titles and conf.nullConnection:
        errMsg = "开关'--titles'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.search:
        errMsg = "开关'--dump'与开关'--search'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.chunked and not any((conf.data, conf.requestFile, conf.forms)):
        errMsg = "开关'--chunked'需要使用（POST）选项/开关'--data'、'-r'或'--forms'"
        raise SqlmapSyntaxException(errMsg)

    if conf.api and not conf.configFile:
        errMsg = "开关'--api'需要使用选项'-c'"
        raise SqlmapSyntaxException(errMsg)

    if conf.data and conf.nullConnection:
        errMsg = "选项'--data'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.nullConnection:
        errMsg = "选项'--string'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.notString and conf.nullConnection:
        errMsg = "选项'--not-string'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.osPwn:
        errMsg = "选项'--tor'与开关'--os-pwn'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.noCast and conf.hexConvert:
        errMsg = "开关'--no-cast'与开关'--hex'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlDepth:
        try:
            xrange(conf.crawlDepth)
        except OverflowError as ex:
            errMsg = "选项'--crawl'使用的值无效 ('%s')" % getSafeExString(ex)
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpAll and conf.search:
        errMsg = "开关'--dump-all'与开关'--search'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.notString:
        errMsg = "选项'--string'与开关'--not-string'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp and conf.nullConnection:
        errMsg = "选项'--regexp'与开关'--null-connection'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp:
        try:
            re.compile(conf.regexp)
        except Exception as ex:
            errMsg = "无效的正则表达式 '%s' ('%s')" % (conf.regexp, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.paramExclude:
        try:
            re.compile(conf.paramExclude)
        except Exception as ex:
            errMsg = "无效的正则表达式 '%s' ('%s')" % (conf.paramExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.retryOn:
        try:
            re.compile(conf.retryOn)
        except Exception as ex:
            errMsg = "无效的正则表达式 '%s' ('%s')" % (conf.retryOn, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

        if conf.retries == defaults.retries:
            conf.retries = 5 * conf.retries

            warnMsg = "增加的默认值 "
            warnMsg += "选项'--retries'设置为 %d 因为 " % conf.retries
            warnMsg += "提供了选项'--retry-on'"
            logger.warning(warnMsg)


    if conf.cookieDel and len(conf.cookieDel) != 1:
        errMsg = "选项'--cookie-del'应包含单个字符（例如 ';'）"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude:
        try:
            re.compile(conf.crawlExclude)
        except Exception as ex:
            errMsg = "无效的正则表达式 '%s' ('%s')" % (conf.crawlExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.scope:
        try:
            re.compile(conf.scope)
        except Exception as ex:
            errMsg = "无效的正则表达式 '%s' ('%s')" % (conf.scope, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.dumpAll:
        errMsg = "开关'--dump'与开关'--转储all'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.predictOutput and (conf.threads > 1 or conf.optimize):
        errMsg = "开关'--predict-output'与选项'--threads'和开关'-o'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.threads > MAX_NUMBER_OF_THREADS and not conf.get("skipThreadCheck"):
        errMsg = "最大使用线程数为 %d 避免了潜在的连接问题" % MAX_NUMBER_OF_THREADS
        raise SqlmapSyntaxException(errMsg)

    if conf.forms and not any((conf.url, conf.googleDork, conf.bulkFile)):
        errMsg = "开关'--forms'需要使用选项'-u'（'--url'）、'-g'或'-m'"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude and not conf.crawlDepth:
        errMsg = "选项'--crawl-exclude'需要使用开关'--craft'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safePost and not conf.safeUrl:
        errMsg = "选项'--safe-post'需要使用选项'--afe-url'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeFreq and not any((conf.safeUrl, conf.safeReqFile)):
        errMsg = "选项'--safe-freq'需要使用选项'--safe-url'或'--afe-req'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeReqFile and any((conf.safeUrl, conf.safePost)):
        errMsg = "选项'--safe-req'与选项'--afe-url'和选项'--sece-post'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfUrl and not conf.csrfToken:
        errMsg = "选项'--csrf-url'需要使用选项'--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfMethod and not conf.csrfToken:
        errMsg = "选项'--csrf-method'需要使用选项'--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfData and not conf.csrfToken:
        errMsg = "选项'--csrf-data'需要使用选项'--csf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfToken and conf.threads > 1:
        errMsg = "选项'--csrf-url'与选项'--threads'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.requestFile and conf.url and conf.url != DUMMY_URL:
        errMsg = "选项'-r'与选项'-u'（'--url'）不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.proxy:
        errMsg = "选项'-d'与选项'--proxy'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.tor:
        errMsg = "选项'-d'与开关'--tor'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if not conf.technique:
        errMsg = "选项'--technique'不能为空"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.ignoreProxy:
        errMsg = "开关'--tor'与开关'--ignore-proxy'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.proxy:
        errMsg = "开关'--tor'与选项'--proxy'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.proxyFile:
        errMsg = "开关'--proxy'与选项'--proxy-file'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFreq and not conf.proxyFile:
        errMsg = "选项'--proxy-freq'需要使用选项'--proxy-file'"
        raise SqlmapSyntaxException(errMsg)

    if conf.checkTor and not any((conf.tor, conf.proxy)):
        errMsg = "开关'--check-tor'需要使用开关'--tor'（或带有tor服务的HTTP代理地址的选项'--proxy'）"
        raise SqlmapSyntaxException(errMsg)

    if conf.torPort is not None and not (isinstance(conf.torPort, int) and conf.torPort >= 0 and conf.torPort <= 65535):
        errMsg = "选项'--tor-port'的值必须在[0，65535]范围内"
        raise SqlmapSyntaxException(errMsg)

    if conf.torType not in getPublicTypeMembers(PROXY_TYPE, True):
        errMsg = "选项'--tor-type'接受以下值之一： %s" % ", ".join(getPublicTypeMembers(PROXY_TYPE, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpFormat not in getPublicTypeMembers(DUMP_FORMAT, True):
        errMsg = "选项'--dump-format'接受以下值之一： %s" % ", ".join(getPublicTypeMembers(DUMP_FORMAT, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.skip and conf.testParameter:
        if intersect(conf.skip, conf.testParameter):
            errMsg = "选项'--skip'与选项'-p'不兼容"
            raise SqlmapSyntaxException(errMsg)

    if conf.rParam and conf.testParameter:
        if intersect(conf.rParam, conf.testParameter):
            errMsg = "选项'--randomize'与选项'-p'不兼容"
            raise SqlmapSyntaxException(errMsg)

    if conf.mobile and conf.agent:
        errMsg = "开关'--mobile'与选项'--user-agent'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.ignoreProxy:
        errMsg = "选项'--proxy'与开关'--ignore-proxy'不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.alert and conf.alert.startswith('-'):
        errMsg = "选项'--alert'的值必须是有效的操作系统命令"
        raise SqlmapSyntaxException(errMsg)

    if conf.timeSec < 1:
        errMsg = "选项'--time-sec'的值必须是正整数"
        raise SqlmapSyntaxException(errMsg)

    if conf.uChar and not re.match(UNION_CHAR_REGEX, conf.uChar):
        errMsg = "选项'--union-char'的值必须是字母数字值（例如1）"
        raise SqlmapSyntaxException(errMsg)

    if conf.hashFile and any((conf.direct, conf.url, conf.logFile, conf.bulkFile, conf.googleDork, conf.configFile, conf.requestFile, conf.updateAll, conf.smokeTest, conf.wizard, conf.dependencies, conf.purge, conf.listTampers)):
        errMsg = "选项'--crack'应单独使用"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.uCols, six.string_types):
        if not conf.uCols.isdigit() and ("-" not in conf.uCols or len(conf.uCols.split("-")) != 2):
            errMsg = "选项'--union-cols'的值必须是带hyphon的范围"
            errMsg += "(e.g. 1-10) 或整数值 (e.g. 5)"
            raise SqlmapSyntaxException(errMsg)

    if conf.dbmsCred and ':' not in conf.dbmsCred:
        errMsg = "选项'--dbms-cred'的值必须 "
        errMsg += "为格式 <username>:<password> (e.g. \"root:pass\")"
        raise SqlmapSyntaxException(errMsg)

    if conf.encoding:
        _ = checkCharEncoding(conf.encoding, False)
        if _ is None:
            errMsg = "未知编码 '%s'. 请访问 " % conf.encoding
            errMsg += "'%s' 获取支持的编码的 " % CODECS_LIST_PAGE
            errMsg += "完整列表"
            raise SqlmapSyntaxException(errMsg)
        else:
            conf.encoding = _

    if conf.fileWrite and not os.path.isfile(conf.fileWrite):
        errMsg = "文件 '%s' 不存在" % os.path.abspath(conf.fileWrite)
        raise SqlmapFilePathException(errMsg)

    if conf.loadCookies and not os.path.exists(conf.loadCookies):
        errMsg = "cookie文件 '%s' 不存在" % os.path.abspath(conf.loadCookies)
        raise SqlmapFilePathException(errMsg)

def initOptions(inputOptions=AttribDict(), overrideOptions=False):
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _mergeOptions(inputOptions, overrideOptions)

def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    _useWizardInterface()
    setVerbosity()
    _saveConfig()
    _setRequestFromFile()
    _cleanupOptions()
    _cleanupEnvironment()
    _purge()
    _checkDependencies()
    _createHomeDirectories()
    _createTemporaryDirectory()
    _basicOptionValidation()
    _setProxyList()
    _setTorProxySettings()
    _setDNSServer()
    _adjustLoggingFormatter()
    _setMultipleTargets()
    _listTamperingFunctions()
    _setTamperingFunctions()
    _setPreprocessFunctions()
    _setPostprocessFunctions()
    _setTrafficOutputFP()
    _setupHTTPCollector()
    _setHttpChunked()
    _checkWebSocket()

    parseTargetDirect()

    if any((conf.url, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.stdinPipe)):
        _setHostname()
        _setHTTPTimeout()
        _setHTTPExtraHeaders()
        _setHTTPCookies()
        _setHTTPReferer()
        _setHTTPHost()
        _setHTTPUserAgent()
        _setHTTPAuthentication()
        _setHTTPHandlers()
        _setDNSCache()
        _setSocketPreConnect()
        _setSafeVisit()
        _doSearch()
        _setStdinPipeTargets()
        _setBulkMultipleTargets()
        _checkTor()
        _setCrawler()
        _findPageForms()
        _setDBMS()
        _setTechnique()

    _setThreads()
    _setOS()
    _setWriteFile()
    _setMetasploit()
    _setDBMSAuthentication()
    loadBoundaries()
    loadPayloads()
    _setPrefixSuffix()
    update()
    _loadQueries()
