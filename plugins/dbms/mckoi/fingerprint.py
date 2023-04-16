#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import MCKOI_ALIASES
from lib.core.settings import MCKOI_DEFAULT_SCHEMA
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MCKOI)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web 服务", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端 DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "

        if not conf.extensiveFp:
            value += DBMS.MCKOI
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "活动指纹: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%s 解析指纹 banner : %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%s html错误消息指纹: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(MCKOI_ALIASES):
            setDbms(DBMS.MCKOI)
            return True

        infoMsg = "测试 %s" % DBMS.MCKOI
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("DATEOB()>=DATEOB(NULL)")

        if result:
            infoMsg = "确认 %s" % DBMS.MCKOI
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("ABS(1/0)>ABS(0/1)")

            if not result:
                warnMsg = "这个 DBMS 不是 %s" % DBMS.MCKOI
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.MCKOI)

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.MCKOI
            logger.warning(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = MCKOI_DEFAULT_SCHEMA
