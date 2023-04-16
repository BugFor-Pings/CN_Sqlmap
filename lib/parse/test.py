import re
import time

import requests

with open('cmdline.py','r') as f:
    pp=f.readlines()



def alter(file,old_str,new_str):
    """
    替换文件中的字符串
    :param file:文件名
    :param old_str:就字符串
    :param new_str:新字符串
    :return:
    """
    file_data = ""
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
            if old_str in line:
                line = line.replace(old_str,new_str)
            file_data += line
    with open(file,"w",encoding="utf-8") as f:
        f.write(file_data)



ppp="".join(pp)
find =re.findall('help="(.*?)"',ppp)
print(find)
for i in find:
    jc = requests.get(url="http://fanyi.youdao.com/translate?&doctype=json&type=AUTO&i="+i)
    find_str=re.findall('"tgt":"(.*?)"',jc.text)
    find_str_1="".join(find_str)
    time.sleep(1)
    print(find_str_1)
    alter("cmdline.py", i, find_str_1)
