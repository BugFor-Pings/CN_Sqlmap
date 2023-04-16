#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                __import__("_mssql")

                pymssql = __import__("pymssql")
                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    warnMsg = "'%s' 第三方库必须是 " % data[1]
                    warnMsg += "版本 >= 1.0.2 正常工作. "
                    warnMsg += "下载'%s'" % data[2]
                    logger.warning(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                __import__("pymysql")
            elif dbmsName in (DBMS.PGSQL, DBMS.CRATEDB):
                __import__("psycopg2")
            elif dbmsName == DBMS.ORACLE:
                __import__("cx_Oracle")
            elif dbmsName == DBMS.SQLITE:
                __import__("sqlite3")
            elif dbmsName == DBMS.ACCESS:
                __import__("pyodbc")
            elif dbmsName == DBMS.FIREBIRD:
                __import__("kinterbasdb")
            elif dbmsName == DBMS.DB2:
                __import__("ibm_db_dbi")
            elif dbmsName in (DBMS.HSQLDB, DBMS.CACHE):
                __import__("jaydebeapi")
                __import__("jpype")
            elif dbmsName == DBMS.INFORMIX:
                __import__("ibm_db_dbi")
            elif dbmsName == DBMS.MONETDB:
                __import__("pymonetdb")
            elif dbmsName == DBMS.DERBY:
                __import__("drda")
            elif dbmsName == DBMS.VERTICA:
                __import__("vertica_python")
            elif dbmsName == DBMS.PRESTO:
                __import__("prestodb")
            elif dbmsName == DBMS.MIMERSQL:
                __import__("mimerpy")
            elif dbmsName == DBMS.CUBRID:
                __import__("CUBRIDdb")
        except:
            warnMsg = "sqlmap需要 '%s' 第三方库 " % data[1]
            warnMsg += "以便直接连接到DBMS "
            warnMsg += "'%s'. 下载 '%s'" % (dbmsName, data[2])
            logger.warning(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "'%s' 找到第三方库" % data[1]
        logger.debug(debugMsg)

    try:
        __import__("impacket")
        debugMsg = "找到'python-impacket' 的第三方库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要 'python-impacket' 第三方库 "
        warnMsg += "带外接管功能 下载 "
        warnMsg += "'https://github.com/coresecurity/impacket'"
        logger.warning(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        __import__("ntlm")
        debugMsg = "找到'python-ntlm'的第三方库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要'python-ntlm'第三方库 "
        warnMsg += "如果计划攻击NTLM背后的web应用程序 "
        warnMsg += "身份验证 下载'https://github.com/mullender/python-ntlm'"
        logger.warning(warnMsg)
        missing_libraries.add('python-ntlm')

    try:
        __import__("websocket._abnf")
        debugMsg = "'找到websocket-client'库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要'websocket-clien'第三方库 "
        warnMsg += "如果您计划使用WebSocket攻击web应用程序。 "
        warnMsg += "下载 来自 'https://pypi.python.org/pypi/websocket-client/'"
        logger.warning(warnMsg)
        missing_libraries.add('websocket-client')

    try:
        __import__("tkinter")
        debugMsg = "'tkinter' 找到了库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要'tkinter'库"
        warnMsg += "如果计划运行GUI"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter')

    try:
        __import__("tkinter.ttk")
        debugMsg = "'tkinter.ttk' 找到了库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要'tkinter.ttk'库 "
        warnMsg += "如果计划运行GUI"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter.ttk')

    if IS_WIN:
        try:
            __import__("pyreadline")
            debugMsg = "找到'python-pyreadline'的第三方库"
            logger.debug(debugMsg)
        except ImportError:
            warnMsg = "sqlmap requires 'pyreadline' third-party library to "
            warnMsg += "be able to take advantage of the sqlmap TAB "
            warnMsg += "completion and history support features in the SQL "
            warnMsg += "shell and OS shell. Download from "
            warnMsg += "'https://pypi.org/project/pyreadline/'"
            logger.warning(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "已安装所有依赖项"
        logger.info(infoMsg)
