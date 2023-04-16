#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import checkFile
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import unArrayizeValue
from lib.core.common import UnicodeRawConfigParser
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import OPTION_TYPE
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.optiondict import optDict

config = None

def configFileProxy(section, option, datatype):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    if config.has_option(section, option):
        try:
            if datatype == OPTION_TYPE.BOOLEAN:
                value = config.getboolean(section, option) if config.get(section, option) else False
            elif datatype == OPTION_TYPE.INTEGER:
                value = config.getint(section, option) if config.get(section, option) else 0
            elif datatype == OPTION_TYPE.FLOAT:
                value = config.getfloat(section, option) if config.get(section, option) else 0.0
            else:
                value = config.get(section, option)
        except ValueError as ex:
            errMsg = "处理选项时出错 "
            errMsg += "'%s' 在提供的配置文件中 ('%s')" % (option, getUnicode(ex))
            raise SqlmapSyntaxException(errMsg)

        if value:
            conf[option] = value
        else:
            conf[option] = None
    else:
        debugMsg = "缺少请求的选项 '%s' (部分 " % option
        debugMsg += "'%s') 到配置文件中, " % section
        debugMsg += "忽略 . 跳到下一个."
        logger.debug(debugMsg)

def configFileParser(configFile):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    debugMsg = "分析配置文件"
    logger.debug(debugMsg)

    checkFile(configFile)
    configFP = openFile(configFile, "rb")

    try:
        config = UnicodeRawConfigParser()
        config.readfp(configFP)
    except Exception as ex:
        errMsg = "您提供了无效和/或不可读的配置文件 ('%s')" % getSafeExString(ex)
        raise SqlmapSyntaxException(errMsg)

    if not config.has_section("Target"):
        errMsg = "配置文件中缺少强制节'Target'"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    mandatory = False

    for option in ("direct", "url", "logFile", "bulkFile", "googleDork", "requestFile", "wizard"):
        if config.has_option("Target", option) and config.get("Target", option) or cmdLineOptions.get(option):
            mandatory = True
            break

    if not mandatory:
        errMsg = "配置文件中缺少强制选项"
        errMsg += "(direct, url, logFile, bulkFile, googleDork, requestFile or wizard)"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    for family, optionData in optDict.items():
        for option, datatype in optionData.items():
            datatype = unArrayizeValue(datatype)
            configFileProxy(family, option, datatype)
