#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "在Presto上，不可能获得横幅"
        logger.warning(warnMsg)

        return None

    def getCurrentDb(self):
        warnMsg = "在Presto上，无法获取当前数据库的名称（模式）"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "在Presto上，无法测试当前用户是否为DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "在Presto上，无法枚举用户"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "在Presto上，无法枚举用户密码哈希"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在Presto上，无法枚举用户权限"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "在Presto上，无法枚举用户角色"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "在Presto上，无法枚举主机名"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在Presto上，无法枚举SQL语句"
        logger.warning(warnMsg)

        return []
