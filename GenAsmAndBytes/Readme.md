把GenAsmAndBytes.idc放到ida安装目录的idc目录下，执行如下命令
```
windows版ida执行
idaw.exe -A -SGenAsmAndBytes.idc Win32Project1.exe2
Linux版ida执行
idal -A -SGenAsmAndBytes.idc Win32Project1.exe2
```
生成Win32Project1.asm和Win32Project1.bytes文件，样本文件见samlple目录。
