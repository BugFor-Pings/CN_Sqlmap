#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import sys
import time

PYVERSION = sys.version.split()[0]

if PYVERSION < "2.6":
    sys.exit("[%s] [关键的] 检测到不兼容的Python版本('%s'). 要成功运行sqlmap，必须使用版本 2.6, 2.7 or 3.x (visit 'https://www.python.org/downloads/')" % (time.strftime("%X"), PYVERSION))

errors = []
extensions = ("bz2", "gzip", "pyexpat", "ssl", "sqlite3", "zlib")
for _ in extensions:
    try:
        __import__(_)
    except ImportError:
        errors.append(_)

if errors:
    errMsg = "[%s] [关键的] 缺少一个或多个核心扩展 (%s) " % (time.strftime("%X"), ", ".join("'%s'" % _ for _ in errors))
    errMsg += "最有可能是因为当前版本的Python "
    errMsg += "构建时没有适当的开发包"
    sys.exit(errMsg)
