#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import readInput
from lib.core.data import logger
from lib.core.enums import OS
from lib.core.exception import SqlmapUndefinedMethod

class Fingerprint(object):
    """
    This class defines generic fingerprint functionalities for plugins.
    """

    def __init__(self, dbms):
        Backend.forceDbms(dbms)

    def getFingerprint(self):
        errMsg = "必须定义'getFingerprint'方法 "
        errMsg += "到特定的DBMS插件"
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbms(self):
        errMsg = "必须定义'checkDbms'方法"
        errMsg += "到特定的DBMS插件"
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbmsOs(self, detailed=False):
        errMsg = "必须定义'checkDbmsOs'方法 "
        errMsg += "到特定的DBMS插件"
        raise SqlmapUndefinedMethod(errMsg)

    def forceDbmsEnum(self):
        pass

    def userChooseDbmsOs(self):
        warnMsg = "由于某种原因，sqlmap无法识别指纹 "
        warnMsg += "后端DBMS操作系统"
        logger.warning(warnMsg)

        msg = "你想提供操作系统吗？ [(W)indows/(l)inux]"

        while True:
            os = readInput(msg, default='W').upper()

            if os == 'W':
                Backend.setOs(OS.WINDOWS)
                break
            elif os == 'L':
                Backend.setOs(OS.LINUX)
                break
            else:
                warnMsg = "无效值"
                logger.warning(warnMsg)
