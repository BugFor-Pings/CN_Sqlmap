#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import re
import shlex
import sys

try:
    from optparse import OptionError as ArgumentError
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser
    from optparse import SUPPRESS_HELP as SUPPRESS
    from lib.core.settings import TRANSLATE

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument_group(self, *args, **kwargs):
        return self.add_option_group(OptionGroup(self, *args, **kwargs))

    ArgumentParser.add_argument_group = _add_argument_group

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser
    from argparse import ArgumentError
    from argparse import SUPPRESS

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import checkOldOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.option import _createHomeDirectories
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORED_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory
from thirdparty.six.moves import input as _input



def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()
    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [options]" % ("%s " % os.path.basename(sys.executable) if not IS_WIN else "", "\"%s\"" % _ if " " in _ else _)
    parser = ArgumentParser(usage=usage)

    try:
        parser.add_argument("--hh", dest="advancedHelp", action="store_true",
            help="展示先进的帮助信息并退出")

        parser.add_argument("--version", dest="showVersion", action="store_true",
            help="显示程序的版本号并退出")

        parser.add_argument("-v", dest="verbose", type=int,
            help="冗长水平:0 - 6(默认 %d)" % defaults.verbose)

        # Target options
        target = parser.add_argument_group("目标", "必须至少提供其中一个选项来定义目标")

        target.add_argument("-u", "--url", dest="url",
            help="目标URL(例如 \"http://www.site.com/vuln.php?id=1\")")

        target.add_argument("-d", dest="direct",
            help="连接字符串直接数据库连接")

        target.add_argument("-l", dest="logFile",
            help="解析目标(s)从打嗝或WebScarab代理日志文件")

        target.add_argument("-m", dest="bulkFile",
            help="扫描多个目标在一个文本文件")

        target.add_argument("-r", dest="requestFile",
            help="从文件中加载HTTP请求")

        target.add_argument("-g", dest="googleDork",
            help="将Google dork结果作为目标URL处理")

        target.add_argument("-c", dest="configFile",
            help="从一个配置加载选项INI文件")

        # Request options
        request = parser.add_argument_group("请求", "这些选项可用于指定如何连接到目标URL")

        request.add_argument("-A", "--user-agent", dest="agent",
            help="HTTP用户代理头的值")

        request.add_argument("-H", "--header", dest="header",
            help="额外的头(例如 \"X-Forwarded-For: 127.0.0.1\")")

        request.add_argument("--method", dest="method",
            help="强制使用给定HTTP方法(例如 PUT)")

        request.add_argument("--data", dest="data",
            help="通过POST发送的数据字符串(例如 \"id=1\")")

        request.add_argument("--param-del", dest="paramDel",
            help="用于拆分参数值的字符(例如 &")

        request.add_argument("--cookie", dest="cookie",
            help="HTTP Cookie头的值(例如 \"PHPSESSID=a8d127e..\")")

        request.add_argument("--cookie-del", dest="cookieDel",
            help="用于拆分cookie值的字符(例如 ;)")

        request.add_argument("--live-cookies", dest="liveCookies",
            help="用于加载最新值的实时cookie文件")

        request.add_argument("--load-cookies", dest="loadCookies",
            help="包含Netscape/wget格式cookie的文件")

        request.add_argument("--drop-set-cookie", dest="dropSetCookie", action="store_true",
            help="忽略响应中的Set Cookie标头")

        request.add_argument("--mobile", dest="mobile", action="store_true",
            help="模仿智能手机通过HTTP代理头")

        request.add_argument("--random-agent", dest="randomAgent", action="store_true",
            help="使用随机选择的HTTP用户代理标头值")

        request.add_argument("--host", dest="host",
            help="HTTP主机头的值")

        request.add_argument("--referer", dest="referer",
            help="HTTP引用页头的值")

        request.add_argument("--headers", dest="headers",
            help="额外的标题(例如\"Accept-Language: fr\\nETag: 123\")")

        request.add_argument("--auth-type", dest="authType",
            help="HTTP身份验证类型(Basic, Digest, Bearer, ...)")

        request.add_argument("--auth-cred", dest="authCred",
            help="HTTP身份验证凭证(名称:密码)")

        request.add_argument("--auth-file", dest="authFile",
            help="HTTP身份验证PEM证书/私钥文件")

        request.add_argument("--ignore-code", dest="ignoreCode",
            help="忽略(问题)的HTTP错误代码(例如: 401)")

        request.add_argument("--ignore-proxy", dest="ignoreProxy", action="store_true",
            help="忽略系统默认代理设置")

        request.add_argument("--ignore-redirects", dest="ignoreRedirects", action="store_true",
            help="忽略重定向的尝试")

        request.add_argument("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
            help="忽略连接超时")

        request.add_argument("--proxy", dest="proxy",
            help="使用一个代理连接到目标URL")

        request.add_argument("--proxy-cred", dest="proxyCred",
            help="代理身份验证凭证(名称:密码)")

        request.add_argument("--proxy-file", dest="proxyFile",
            help="从文件加载代理列表")

        request.add_argument("--proxy-freq", dest="proxyFreq", type=int,
            help="请求改变之间的代理从一个给定的列表")

        request.add_argument("--tor", dest="tor", action="store_true",
            help="使用Tor匿名网络")

        request.add_argument("--tor-port", dest="torPort",
            help="设置Tor代理端口,而不是默认值")

        request.add_argument("--tor-type", dest="torType",
            help="设置Tor代理类型(HTTP、SOCKS4或SOCKS5(默认)")

        request.add_argument("--check-tor", dest="checkTor", action="store_true",
            help="查看是否正确使用Tor")

        request.add_argument("--delay", dest="delay", type=float,
            help="每个HTTP请求之间的延迟（秒）")

        request.add_argument("--timeout", dest="timeout", type=float,
            help="超时连接前等待的秒数(默认值 %d)" % defaults.timeout)

        request.add_argument("--retries", dest="retries", type=int,
            help="重试时连接超时(默认 %d)" % defaults.retries)

        request.add_argument("--retry-on", dest="retryOn",
            help="对匹配内容的正则表达式重试请求(例如 \"drop\")")

        request.add_argument("--randomize", dest="rParam",
            help="对于给定的参数随机变化值(s)")

        request.add_argument("--safe-url", dest="safeUrl",
            help="URL地址访问期间经常测试")

        request.add_argument("--safe-post", dest="safePost",
            help="POST数据发送到一个安全的URL")

        request.add_argument("--safe-req", dest="safeReqFile",
            help="从一个文件装载安全的HTTP请求")

        request.add_argument("--safe-freq", dest="safeFreq", type=int,
            help="定期请求访问一个安全的URL")

        request.add_argument("--skip-urlencode", dest="skipUrlEncode", action="store_true",
            help="跳过URL编码的有效载荷数据")

        request.add_argument("--csrf-token", dest="csrfToken",
            help="参数用于保存anti-CSRF令牌")

        request.add_argument("--csrf-url", dest="csrfUrl",
            help="URL地址为提取anti-CSRF访问令牌")

        request.add_argument("--csrf-method", dest="csrfMethod",
            help="HTTP方法使用anti-CSRF标记页面访问期间")

        request.add_argument("--csrf-data", dest="csrfData",
            help="POST数据发送anti-CSRF标记页面访问期间")

        request.add_argument("--csrf-retries", dest="csrfRetries", type=int,
            help="重试anti-CSRF令牌检索(默认 %d)" % defaults.csrfRetries)

        request.add_argument("--force-ssl", dest="forceSSL", action="store_true",
            help="强制使用SSL/HTTPS")

        request.add_argument("--chunked", dest="chunked", action="store_true",
            help="使用HTTP分块传输编码(POST)请求")

        request.add_argument("--hpp", dest="hpp", action="store_true",
            help="使用HTTP参数污染的方法")

        request.add_argument("--eval", dest="evalCode",
            help="请求之前评估提供Python代码(例如 \"import hashlib;id2=hashlib.md5(id).hexdigest()\")")

        # Optimization options
        optimization = parser.add_argument_group("优化", "这些选项可用于优化sqlmap的性能")

        optimization.add_argument("-o", dest="optimize", action="store_true",
            help="打开所有优化开关")

        optimization.add_argument("--predict-output", dest="predictOutput", action="store_true",
            help="预测常见的查询输出")

        optimization.add_argument("--keep-alive", dest="keepAlive", action="store_true",
            help="使用持久HTTP (s)连接")

        optimization.add_argument("--null-connection", dest="nullConnection", action="store_true",
            help="检索页面长度没有实际的HTTP响应的身体")

        optimization.add_argument("--threads", dest="threads", type=int,
            help="最大并发HTTP (s)请求(默认 %d)" % defaults.threads)

        # Injection options
        injection = parser.add_argument_group("注射", "这些选项可用于指定要测试的参数、提供自定义注入有效载荷和可选的篡改脚本")

        injection.add_argument("-p", dest="testParameter",
            help="可测试参数")

        injection.add_argument("--skip", dest="skip",
            help="跳过测试对于给定参数(s)")

        injection.add_argument("--skip-static", dest="skipStatic", action="store_true",
            help="跳过测试参数不似乎是动态的")

        injection.add_argument("--param-exclude", dest="paramExclude",
            help="Regexp排除参数测试(例如 \"ses\")")

        injection.add_argument("--param-filter", dest="paramFilter",
            help="选择测试的参数(s)的位置(例如 \"POST\")")

        injection.add_argument("--dbms", dest="dbms",
            help="强制后端DBMS提供值")

        injection.add_argument("--dbms-cred", dest="dbmsCred",
            help="DBMS身份验证凭据(用户:密码)")

        injection.add_argument("--os", dest="os",
            help="强制后端DBMS操作系统提供价值")

        injection.add_argument("--invalid-bignum", dest="invalidBignum", action="store_true",
            help="使用大量无效值")

        injection.add_argument("--invalid-logical", dest="invalidLogical", action="store_true",
            help="使用逻辑操作无效值")

        injection.add_argument("--invalid-string", dest="invalidString", action="store_true",
            help="使用随机字符串无效值")

        injection.add_argument("--no-cast", dest="noCast", action="store_true",
            help="关掉负载铸造机制")

        injection.add_argument("--no-escape", dest="noEscape", action="store_true",
            help="关掉字符串转义机制")

        injection.add_argument("--prefix", dest="prefix",
            help="注入载荷前缀字符串")

        injection.add_argument("--suffix", dest="suffix",
            help="注入载荷后缀字符串")

        injection.add_argument("--tamper", dest="tamper",
            help="使用给定的脚本(s)篡改注入数据")

        # Detection options
        detection = parser.add_argument_group("侦查", "这些选项可用于自定义检测阶段")

        detection.add_argument("--level", dest="level", type=int,
            help="要执行的测试的水平(1-5,默认 %d)" % defaults.level)

        detection.add_argument("--risk", dest="risk", type=int,
            help="要执行的测试的风险(1-3,默认 %d)" % defaults.risk)

        detection.add_argument("--string", dest="string",
            help="查询字符串来匹配时求值为True")

        detection.add_argument("--not-string", dest="notString",
            help="字符串匹配时查询计算为False")

        detection.add_argument("--regexp", dest="regexp",
            help="Regexp匹配查询时求值为True")

        detection.add_argument("--code", dest="code", type=int,
            help="HTTP代码查询评估为True时匹配")

        detection.add_argument("--smart", dest="smart", action="store_true",
            help="进行彻底的测试只有在积极的启发式(s)")

        detection.add_argument("--text-only", dest="textOnly", action="store_true",
            help="页面只基于文本内容进行比较")

        detection.add_argument("--titles", dest="titles", action="store_true",
            help="比较页面仅基于他们的头衔")

        # Techniques options
        techniques = parser.add_argument_group("技术", "这些选项可用于调整特定SQL注入技术的测试")

        techniques.add_argument("--technique", dest="technique",
            help="要使用的SQL注入技术(默认 \"%s\")" % defaults.technique)

        techniques.add_argument("--time-sec", dest="timeSec", type=int,
            help="秒延迟DBMS响应(默认 %d)" % defaults.timeSec)

        techniques.add_argument("--union-cols", dest="uCols",
            help="列的SQL注入的测试联合查询")

        techniques.add_argument("--union-char", dest="uChar",
            help="字符用于bruteforcing列数")

        techniques.add_argument("--union-from", dest="uFrom",
            help="UNION查询SQL注入的FROM部分中使用的表")

        techniques.add_argument("--dns-domain", dest="dnsDomain",
            help="域名用于DNS漏出攻击")

        techniques.add_argument("--second-url", dest="secondUrl",
            help="产生的页面的URL搜索二阶响应")

        techniques.add_argument("--second-req", dest="secondReq",
            help="从文件加载二阶HTTP请求")

        # Fingerprint options
        fingerprint = parser.add_argument_group("Fingerprint")

        fingerprint.add_argument("-f", "--fingerprint", dest="extensiveFp", action="store_true",
            help="执行一个广泛的DBMS版本指纹")

        # Enumeration options
        enumeration = parser.add_argument_group("枚举", "这些选项可用于枚举表中包含的后端数据库管理系统信息、结构和数据")

        enumeration.add_argument("-a", "--all", dest="getAll", action="store_true",
            help="检索所有")

        enumeration.add_argument("-b", "--banner", dest="getBanner", action="store_true",
            help="检索DBMS横幅")

        enumeration.add_argument("--current-user", dest="getCurrentUser", action="store_true",
            help="获取当前用户数据库管理系统")

        enumeration.add_argument("--current-db", dest="getCurrentDb", action="store_true",
            help="检索DBMS当前数据库")

        enumeration.add_argument("--hostname", dest="getHostname", action="store_true",
            help="检索DBMS服务器主机名")

        enumeration.add_argument("--is-dba", dest="isDba", action="store_true",
            help="检测是否DBA DBMS当前用户")

        enumeration.add_argument("--users", dest="getUsers", action="store_true",
            help="列举DBMS用户")

        enumeration.add_argument("--passwords", dest="getPasswordHashes", action="store_true",
            help="列举DBMS用户 password hashes")

        enumeration.add_argument("--privileges", dest="getPrivileges", action="store_true",
            help="列举DBMS用户 privileges")

        enumeration.add_argument("--roles", dest="getRoles", action="store_true",
            help="列举DBMS用户 roles")

        enumeration.add_argument("--dbs", dest="getDbs", action="store_true",
            help="列举DBMS数据库")

        enumeration.add_argument("--tables", dest="getTables", action="store_true",
            help="列举DBMS数据库表")

        enumeration.add_argument("--columns", dest="getColumns", action="store_true",
            help="列举DBMS数据库表列")

        enumeration.add_argument("--schema", dest="getSchema", action="store_true",
            help="Enumerate DBMS schema")

        enumeration.add_argument("--count", dest="getCount", action="store_true",
            help="检索表(s)的条目数量")

        enumeration.add_argument("--dump", dest="dumpTable", action="store_true",
            help="转储DBMS数据库表条目")

        enumeration.add_argument("--dump-all", dest="dumpAll", action="store_true",
            help="转储所有DBMS数据库表条目")

        enumeration.add_argument("--search", dest="search", action="store_true",
            help="搜索列、表和/或数据库名称")

        enumeration.add_argument("--comments", dest="getComments", action="store_true",
            help="枚举期间检查DBMS注释")

        enumeration.add_argument("--statements", dest="getStatements", action="store_true",
            help="检索SQL语句被运行在DBMS")

        enumeration.add_argument("-D", dest="db",
            help="数据库管理系统数据库来列举")

        enumeration.add_argument("-T", dest="tbl",
            help="数据库管理系统数据库表(s)列举")

        enumeration.add_argument("-C", dest="col",
            help="数据库管理系统数据库表列(s)枚举")

        enumeration.add_argument("-X", dest="exclude",
            help="数据库管理系统数据库标识符(s)不列举")

        enumeration.add_argument("-U", dest="user",
            help="DBMS用户列举")

        enumeration.add_argument("--exclude-sysdbs", dest="excludeSysDbs", action="store_true",
            help="列举表时排除DBMS系统数据库")

        enumeration.add_argument("--pivot-column", dest="pivotColumn",
            help="主列名称")

        enumeration.add_argument("--where", dest="dumpWhere",
            help="使用条件而表倾销")

        enumeration.add_argument("--start", dest="limitStart", type=int,
            help="第一个转储表条目检索")

        enumeration.add_argument("--stop", dest="limitStop", type=int,
            help="去年转储表条目检索")

        enumeration.add_argument("--first", dest="firstChar", type=int,
            help="第一个查询输出单词字符检索")

        enumeration.add_argument("--last", dest="lastChar", type=int,
            help="最后输出单词字符检索查询")

        enumeration.add_argument("--sql-query", dest="sqlQuery",
            help="要执行的SQL语句")

        enumeration.add_argument("--sql-shell", dest="sqlShell", action="store_true",
            help="提示一个交互式SQL壳")

        enumeration.add_argument("--sql-file", dest="sqlFile",
            help="从给定的文件执行的SQL语句(s)")

        # Brute force options
        brute = parser.add_argument_group("蛮力破解", "这些选项可用于运行暴力检查")

        brute.add_argument("--common-tables", dest="commonTables", action="store_true",
            help="检查存在的常见的表")

        brute.add_argument("--common-columns", dest="commonColumns", action="store_true",
            help="检查是否存在共同的列")

        brute.add_argument("--common-files", dest="commonFiles", action="store_true",
            help="检查公共文件的存在")

        # User-defined function options
        udf = parser.add_argument_group("用户定义函数注入", "这些选项可用于创建自定义用户定义函数")

        udf.add_argument("--udf-inject", dest="udfInject", action="store_true",
            help="注入自定义用户定义函数")

        udf.add_argument("--shared-lib", dest="shLib",
            help="共享库的本地路径")

        # File system options
        filesystem = parser.add_argument_group("文件系统访问", "这些选项可用于访问后端数据库管理系统底层文件系统")

        filesystem.add_argument("--file-read", dest="fileRead",
            help="读取一个文件从文件系统后端数据库管理系统")

        filesystem.add_argument("--file-write", dest="fileWrite",
            help="写一个本地文件的后端数据库管理系统的文件系统")

        filesystem.add_argument("--file-dest", dest="fileDest",
            help="后端DBMS绝对filepath写")

        # Takeover options
        takeover = parser.add_argument_group("操作系统访问", "这些选项可用于访问后端数据库管理系统底层操作系统")

        takeover.add_argument("--os-cmd", dest="osCmd",
            help="执行一个操作系统命令")

        takeover.add_argument("--os-shell", dest="osShell", action="store_true",
            help="提示一个交互式操作系统shell")

        takeover.add_argument("--os-pwn", dest="osPwn", action="store_true",
            help="OOB shell提示,Meterpreter或VNC")

        takeover.add_argument("--os-smbrelay", dest="osSmb", action="store_true",
            help="一个点击提示OOB壳,Meterpreter或VNC")

        takeover.add_argument("--os-bof", dest="osBof", action="store_true",
            help="存储过程缓冲区溢出"
                                 "exploitation")

        takeover.add_argument("--priv-esc", dest="privEsc", action="store_true",
            help="数据库处理用户特权升级")

        takeover.add_argument("--msf-path", dest="msfPath",
            help="地方道路Metasploit框架安装")

        takeover.add_argument("--tmp-path", dest="tmpPath",
            help="远程临时文件目录的绝对路径")

        # Windows registry options
        windows = parser.add_argument_group("Windows注册表访问", "这些选项可用于访问后端数据库管理系统Windows注册表")

        windows.add_argument("--reg-read", dest="regRead", action="store_true",
            help="读一个Windows注册表键值")

        windows.add_argument("--reg-add", dest="regAdd", action="store_true",
            help="写一个Windows注册表键值数据")

        windows.add_argument("--reg-del", dest="regDel", action="store_true",
            help="删除一个Windows注册表键值")

        windows.add_argument("--reg-key", dest="regKey",
            help="Windows注册表键")

        windows.add_argument("--reg-value", dest="regVal",
            help="Windows注册表键 value")

        windows.add_argument("--reg-data", dest="regData",
            help="Windows注册表键 value data")

        windows.add_argument("--reg-type", dest="regType",
            help="Windows注册表键 value type")

        # General options
        general = parser.add_argument_group("全体的", "这些选项可用于设置一些常规工作参数")

        general.add_argument("-s", dest="sessionFile",
            help="从一个存储加载会话(.sqlite)文件")

        general.add_argument("-t", dest="trafficFile",
            help="记录所有HTTP流量到一个文本文件中")

        general.add_argument("--answers", dest="answers",
            help="预定义的答案(例如 \"quit=N,follow=N\")")

        general.add_argument("--base64", dest="base64Parameter",
            help="包含Base64编码数据的参数(年代)")

        general.add_argument("--base64-safe", dest="base64Safe", action="store_true",
            help="使用URL和文件名安全Base64字母表(RFC 4648)")

        general.add_argument("--batch", dest="batch", action="store_true",
            help="从来没有要求用户输入,使用默认的行为")

        general.add_argument("--binary-fields", dest="binaryFields",
            help="结果字段有二进制值(例如 \"digest\")")

        general.add_argument("--check-internet", dest="checkInternet", action="store_true",
            help="检查网络连接之前评估的目标")

        general.add_argument("--cleanup", dest="cleanup", action="store_true",
            help="清理的DBMS sqlmap特定UDF和表")

        general.add_argument("--crawl", dest="crawlDepth", type=int,
            help="爬行网站从目标URL")

        general.add_argument("--crawl-exclude", dest="crawlExclude",
            help="Regexp排除页面爬行(例如 \"logout\")")

        general.add_argument("--csv-del", dest="csvDel",
            help="(CSV输出中使用的分隔字符 (默认 \"%s\")" % defaults.csvDel)

        general.add_argument("--charset", dest="charset",
            help="盲SQL注入字符集(例如 \"0123456789abcdef\")")

        general.add_argument("--dump-file", dest="dumpFile",
            help="将数据存储到一个自定义文件")

        general.add_argument("--dump-format", dest="dumpFormat",
            help="了数据的格式(CSV(默认)、HTML或SQLITE)")

        general.add_argument("--encoding", dest="encoding",
            help="字符编码用于数据检索(例如GBK)")

        general.add_argument("--eta", dest="eta", action="store_true",
            help="预计到达时间为每个输出显示")

        general.add_argument("--flush-session", dest="flushSession", action="store_true",
            help="冲洗会话文件当前的目标")

        general.add_argument("--forms", dest="forms", action="store_true",
            help="解析和测试目标URL形式")

        general.add_argument("--fresh-queries", dest="freshQueries", action="store_true",
            help="忽略查询结果存储在会话文件中")

        general.add_argument("--gpage", dest="googlePage", type=int,
            help="使用指定页码的Google dork结果")

        general.add_argument("--har", dest="harFile",
            help="记录所有HTTP流量HAR文件")

        general.add_argument("--hex", dest="hexConvert", action="store_true",
            help="在数据检索使用十六进制转换")

        general.add_argument("--output-dir", dest="outputDir", action="store",
            help="自定义输出目录路径")

        general.add_argument("--parse-errors", dest="parseErrors", action="store_true",
            help="从响应解析和显示DBMS的错误消息")

        general.add_argument("--preprocess", dest="preprocess",
            help="使用给定的脚本(s)预处理(请求)")

        general.add_argument("--postprocess", dest="postprocess",
            help="使用给定的脚本(s)后处理(响应)")

        general.add_argument("--repair", dest="repair", action="store_true",
            help="Redump条目有未知字符标记(% s)" % INFERENCE_UNKNOWN_CHAR)

        general.add_argument("--save", dest="saveConfig",
            help="保存选项来配置INI文件")

        general.add_argument("--scope", dest="scope",
            help="Regexp过滤目标")

        general.add_argument("--skip-heuristics", dest="skipHeuristics", action="store_true",
            help="跳过启发式检测漏洞")

        general.add_argument("--skip-waf", dest="skipWaf", action="store_true",
            help="跳过WAF/IPS保护的启发式检测")

        general.add_argument("--table-prefix", dest="tablePrefix",
            help="前缀用于临时表(默认值: \"%s\")" % defaults.tablePrefix)

        general.add_argument("--test-filter", dest="testFilter",
            help="按有效载荷和/或标题选择测试(例如 ROW)")

        general.add_argument("--test-skip", dest="testSkip",
            help="按有效载荷和/或标题跳过测试(例如 BENCHMARK)")

        general.add_argument("--web-root", dest="webRoot",
            help="Web服务器的文档根目录(例如 \"/var/www\")")

        # Miscellaneous options
        miscellaneous = parser.add_argument_group("混杂的", "这些选项不属于任何其他类别")

        miscellaneous.add_argument("-z", dest="mnemonics",
            help="使用短助记符(例如 \"flu,bat,ban,tec=EU\")")

        miscellaneous.add_argument("--alert", dest="alert",
            help="运行主机操作系统命令(s) SQL注入时发现")

        miscellaneous.add_argument("--beep", dest="beep", action="store_true",
            help="出现问题和/或发现漏洞时发出蜂鸣声")

        miscellaneous.add_argument("--dependencies", dest="dependencies", action="store_true",
            help="检查丢失(可选)sqlmap依赖性")

        miscellaneous.add_argument("--disable-coloring", dest="disableColoring", action="store_true",
            help="禁用控制台输出颜色")

        miscellaneous.add_argument("--list-tampers", dest="listTampers", action="store_true",
            help="显示列表可用夯的脚本")

        miscellaneous.add_argument("--no-logging", dest="noLogging", action="store_true",
            help="禁用日志记录到一个文件")

        miscellaneous.add_argument("--offline", dest="offline", action="store_true",
            help="在离线模式下工作(只使用会话数据)")

        miscellaneous.add_argument("--purge", dest="purge", action="store_true",
            help="从sqlmap数据目录中安全地删除所有内容")

        miscellaneous.add_argument("--results-file", dest="resultsFile",
            help="在多个目标模式下结果CSV文件的位置")

        miscellaneous.add_argument("--shell", dest="shell", action="store_true",
            help="提示一个交互式sqlmap壳")

        miscellaneous.add_argument("--tmp-dir", dest="tmpDir",
            help="本地目录用于存储临时文件")

        miscellaneous.add_argument("--unstable", dest="unstable", action="store_true",
            help="调整选项不稳定的连接")

        miscellaneous.add_argument("--update", dest="updateAll", action="store_true",
            help="更新sqlmap")

        miscellaneous.add_argument("--wizard", dest="wizard", action="store_true",
            help="为新手用户简单的向导界面")

        # Hidden and/or experimental options
        parser.add_argument("--crack", dest="hashFile",
            help=SUPPRESS)  # "Load and crack hashes from a file (standalone)"

        parser.add_argument("--dummy", dest="dummy", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--yuge", dest="yuge", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--murphy-rate", dest="murphyRate", type=int,
            help=SUPPRESS)

        parser.add_argument("--debug", dest="debug", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--deprecations", dest="deprecations", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-multi", dest="disableMulti", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-precon", dest="disablePrecon", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-stats", dest="disableStats", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--profile", dest="profile", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--localhost", dest="localhost", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-dbms", dest="forceDbms",
            help=SUPPRESS)

        parser.add_argument("--force-dns", dest="forceDns", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-partial", dest="forcePartial", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-pivoting", dest="forcePivoting", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--ignore-stdin", dest="ignoreStdin", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--non-interactive", dest="nonInteractive", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--gui", dest="gui", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--smoke-test", dest="smokeTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--vuln-test", dest="vulnTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-json", dest="disableJson", action="store_true",
            help=SUPPRESS)

        # API options
        parser.add_argument("--api", dest="api", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--taskid", dest="taskid",
            help=SUPPRESS)

        parser.add_argument("--database", dest="database",
            help=SUPPRESS)

        # Dirty hack to display longer options without breaking into two lines
        if hasattr(parser, "formatter"):
            def _(self, *args):
                retVal = parser.formatter._format_option_strings(*args)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
                return retVal

            parser.formatter._format_option_strings = parser.formatter.format_option_strings
            parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
        else:
            def _format_action_invocation(self, action):
                retVal = self.__format_action_invocation(action)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retVal
                return retVal

            parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
            parser.formatter_class._format_action_invocation = _format_action_invocation

        # Dirty hack for making a short option '-hh'
        if hasattr(parser, "get_option"):
            option = parser.get_option("--hh")
            option._short_opts = ["-hh"]
            option._long_opts = []
        else:
            for action in get_actions(parser):
                if action.option_strings == ["--hh"]:
                    action.option_strings = ["-hh"]
                    break

        # Dirty hack for inherent help message of switch '-h'
        if hasattr(parser, "get_option"):
            option = parser.get_option("-h")
            option.help = option.help.capitalize().replace("this help", "basic help")
        else:
            for action in get_actions(parser):
                if action.option_strings == ["-h", "--help"]:
                    action.help = action.help.capitalize().replace("this help", "basic help")
                    break

        _ = []
        advancedHelp = True
        extraHeaders = []
        auxIndexes = {}

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkOldOptions(argv)

        if "--gui" in argv:
            from lib.core.gui import runGui

            runGui(parser)

            raise SqlmapSilentQuitException

        elif "--shell" in argv:
            _createHomeDirectories()

            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            commands = set(("x", "q", "exit", "quit", "clear"))
            commands.update(get_all_options(parser))

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=commands)

            while True:
                command = None
                prompt = "sqlmap > "

                try:
                    # Note: in Python2 command should not be converted to Unicode before passing to shlex (Reference: https://bugs.python.org/issue1170)
                    command = _input(prompt).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    raise SqlmapShellQuitException

                command = re.sub(r"(?i)\Anew\s+", "", command or "")

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout("[i] 历史记录已清除\n")
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    if not re.search(r"(?i)\A(\?|help)\Z", command):
                        dataToStdout("[!] 提供的选项无效\n")
                    dataToStdout("[i] 有效的例子: '-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError as ex:
                raise SqlmapSyntaxException("在命令行分析过程中出错('%s')" % getSafeExString(ex))

        longOptions = set(re.findall(r"\-\-([^= ]+?)=", parser.format_help()))
        longSwitches = set(re.findall(r"\-\-([^= ]+?)\s", parser.format_help()))

        for i in xrange(len(argv)):
            # Reference: https://en.wiktionary.org/wiki/-
            argv[i] = re.sub(u"\\A(\u2010|\u2013|\u2212|\u2014|\u4e00|\u1680|\uFE63|\uFF0D)+", lambda match: '-' * len(match.group(0)), argv[i])

            # Reference: https://unicode-table.com/en/sets/quotation-marks/
            argv[i] = argv[i].strip(u"\u00AB\u2039\u00BB\u203A\u201E\u201C\u201F\u201D\u2019\u275D\u275E\u276E\u276F\u2E42\u301D\u301E\u301F\uFF02\u201A\u2018\u201B\u275B\u275C")

            if argv[i] == "-hh":
                argv[i] = "-h"
            elif i == 1 and re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", argv[i]) is not None:
                argv[i] = "--url=%s" % argv[i]
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!]从Internet复制粘贴非法（非控制台）引号字符是非法的 (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] 从Internet复制粘贴非法（非控制台）逗号字符是非法的 (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] 检测到可能写入错误 (illegal '=') 的短选项 ('%s')\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w{3,}", argv[i]):
                if argv[i].strip('-').split('=')[0] in (longOptions | longSwitches):
                    argv[i] = "-%s" % argv[i]
            elif argv[i] in IGNORED_OPTIONS:
                argv[i] = ""
            elif argv[i] in DEPRECATED_OPTIONS:
                argv[i] = ""
            elif argv[i].startswith("--data-raw"):
                argv[i] = argv[i].replace("--data-raw", "--data", 1)
            elif argv[i].startswith("--auth-creds"):
                argv[i] = argv[i].replace("--auth-creds", "--auth-cred", 1)
            elif argv[i].startswith("--drop-cookie"):
                argv[i] = argv[i].replace("--drop-cookie", "--drop-set-cookie", 1)
            elif re.search(r"\A(--(tamper|ignore-code|skip))(?!-)", argv[i]):
                key = re.search(r"\-?\-(\w+)\b", argv[i]).group(1)
                index = auxIndexes.get(key, None)
                if index is None:
                    index = i if '=' in argv[i] else (i + 1 if i + 1 < len(argv) and not argv[i + 1].startswith('-') else None)
                    auxIndexes[key] = index
                else:
                    delimiter = ','
                    argv[index] = "%s%s%s" % (argv[index], delimiter, argv[i].split('=')[1] if '=' in argv[i] else (argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith('-') else ""))
                    argv[i] = ""
            elif argv[i] in ("-H", "--header") or any(argv[i].startswith("%s=" % _) for _ in ("-H", "--header")):
                if '=' in argv[i]:
                    extraHeaders.append(argv[i].split('=', 1)[1])
                elif i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif argv[i] == "--deps":
                argv[i] = "--dependencies"
            elif argv[i] == "--disable-colouring":
                argv[i] = "--disable-coloring"
            elif argv[i] == "-r":
                for j in xrange(i + 2, len(argv)):
                    value = argv[j]
                    if os.path.isfile(value):
                        argv[i + 1] += ",%s" % value
                        argv[j] = ''
                    else:
                        break
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print(VERSION_STRING.split('/')[-1])
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
                advancedHelp = False
                for group in get_groups(parser)[:]:
                    found = False
                    for option in get_actions(group):
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS
                        else:
                            found = True
                    if not found:
                        get_groups(parser).remove(group)
            elif '=' in argv[i] and not argv[i].startswith('-') and argv[i].split('=')[0] in longOptions and re.search(r"\A-{1,2}\w", argv[i - 1]) is None:
                dataToStdout("[!] 检测到使用了不带起始连字符的长选项 ('%s')\n" % argv[i])
                raise SystemExit

        for verbosity in (_ for _ in argv if re.search(r"\A\-v+\Z", _)):
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v')
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
        except UnicodeEncodeError as ex:
            dataToStdout("\n[!] %s\n" % getUnicode(ex.object.encode("unicode-escape")))
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                dataToStdout("\n[!] 要查看选项的完整列表，请使用'-hh'\n")
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), args.api, args.ignoreStdin, "GITHUB_ACTIONS" in os.environ)):
            args.stdinPipe = iter(sys.stdin.readline, None)
        else:
            args.stdinPipe = None

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, args.requestFile, args.updateAll, args.smokeTest, args.vulnTest, args.wizard, args.dependencies, args.purge, args.listTampers, args.hashFile, args.stdinPipe)):
            errMsg = "缺少强制选项 (-d, -u, -l, -m, -r, -g, -c, --wizard, --shell, --update, --purge, --list-tampers or --dependencies). "
            errMsg += "使用-h表示基本帮助，使用-hh表示高级帮助\n"
            parser.error(errMsg)

        return args

    except (ArgumentError, TypeError) as ex:
        parser.error(ex)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN and "--non-interactive" not in sys.argv:
            dataToStdout("\n按Enter键继续...")
            _input()
        raise

    debugMsg = "分析命令行"
    logger.debug(debugMsg)
