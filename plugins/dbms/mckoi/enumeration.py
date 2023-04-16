#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "在Mckoi上，不可能获得banner"
        logger.warning(warnMsg)

        return None

    def getCurrentUser(self):
        warnMsg = "在Mckoi上，无法枚举当前用户"
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = "在Mckoi上，无法获取当前数据库的名称"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "在Mckoi上，无法测试当前用户是否为DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "在Mckoi上，无法枚举用户"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "在Mckoi上，无法枚举用户密码哈希"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在Mckoi上，无法枚举用户权限"
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "在Mckoi上，无法枚举数据库 (仅限使用 '--tables')"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = "在Mckoi上，无法搜索数据库"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "在Mckoi上无法搜索表"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "在Mckoi上无法搜索列"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "在Mckoi上搜索选项不可用"
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = "在Mckoi上，无法枚举主机名"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在Mckoi上，无法枚举SQL语句"
        logger.warning(warnMsg)

        return []
