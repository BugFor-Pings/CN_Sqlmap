# CN_Sqlmap
sqlmap 是一种开源渗透测试工具，可自动检测和利用 SQL 注入缺陷并接管数据库服务器。它配备了强大的检测引擎、终极渗透测试仪的许多利基功能，以及广泛的开关，包括数据库指纹识别、从数据库获取数据、访问底层文件系统以及通过带外连接在操作系统上执行命令。

The Chinese version of sqlmap is very friendly to friends who are not good at English. This project comes from sqlmap Chinese, support Python3 and the whole system, v2 details have also been Chinese, full open source without any backdoor

截图
----
![Screenshot](https://blog.hackersafe.cn/usr/uploads/2023/04/2008154009.png)
![Screenshot](https://blog.hackersafe.cn/usr/uploads/2023/04/3557448478.png)
![Screenshot](https://blog.hackersafe.cn/usr/uploads/2023/04/2487631865.png)

实际运行截图：
![Screenshot](https://blog.hackersafe.cn/usr/uploads/2023/04/2584965377.jpg)
![Screenshot](https://blog.hackersafe.cn/usr/uploads/2023/04/1893377604.png)

安装
----
您可以在该仓库中的Releases下载最新的压缩包

你也可以点击 [这里](https://github.com/BugFor-Pings/CN_Sqlmap/releases/download/V1.7.1.1/sqlmap_CN.zip)下载最新的汉化版sqlmap


sqlmap在任何平台上都可以与Python版本2.6，2.7和3.x开箱即用。（目前只测试了python3，未测试python2）

如果你连sqlmap相关命令都记不清的话，可以前往另外一个项目下载Gui图形化界面的sqlmap版本

点击 [这里](https://github.com/BugFor-Pings/Sqlmap_Gui/archive/refs/heads/main.zip)下载GUI图形化界面的Sqlmap

用法
----
要获取基本选项和开关的列表，请使用：
```
python sqlmap.py -h
```
要获取所有选项和开关的列表，请使用：
```
python sqlmap.py -hh
```
可以在此处找到示例运行。要获得 sqlmap 功能的概述、支持的功能列表、所有选项和开关的说明以及示例，建议您查阅用户手册。

链接
----
* 使用手册: https://github.com/sqlmapproject/sqlmap/wiki
* 常见问题 (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ

免责声明
----
由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。


[![Star History Chart](https://api.star-history.com/svg?repos=BugFor-Pings/CN_Sqlmap&type=Date)](https://star-history.com/#BugFor-Pings/CN_Sqlmap&Date)
