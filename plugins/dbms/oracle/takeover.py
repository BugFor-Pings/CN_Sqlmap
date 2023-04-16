#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "尚未为Oracle实施操作系统"
        errMsg += "命令执行功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "尚未为Oracle实施操作系统 "
        errMsg += " 外壳功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "尚未为Oracle实施操作系统"
        errMsg += "带外控制功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = " 尚未为Oracle实施一键操作系统"
        errMsg += "带外控制功能"
        raise SqlmapUnsupportedFeatureException(errMsg)
