# argus
Argus is a malware analysis platform built with Vue 3 and Python

### 系统依赖
* strings相关
apt-get install binutils

* TLSH相关
apt-get install -y libssl-dev

* magic相关
apt-get install -y libmagic1 python3-magic

* ssdeep相关
apt-get install -y ssdeep

* exiftool相关
apt install libimage-exiftool-perl

* yara相关
apt-get install yara

## PE节区信息
Windows 资源语言和子语言的官方定义可以在以下位置找到：
Windows SDK 头文件：
winnt.h 文件中包含了完整的语言和子语言定义
路径通常在：C:\Program Files (x86)\Windows Kits\10\Include\<version>\um\winnt.h
MSDN 文档：
语言标识符：https://learn.microsoft.com/en-us/windows/win32/intl/language-identifiers
子语言标识符：https://learn.microsoft.com/en-us/windows/win32/intl/sublanguage-identifiers
Windows API 参考：
LANGID 和 SUBLANGID 宏的定义
MAKELANGID 和 MAKESUBLANGID 宏的使用方法