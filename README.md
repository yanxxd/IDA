This repository is used to store IDA related data, include idc scripts, python scripts, plug-in code and so on.  

# 1. IDC
name     | comment
-------- | -----
[GenAsmAndBytes](GenAsmAndBytes) | Generate .asm file and .bytes file in Kaggle2015 format from binary. |

# 2. IDAPython
name     | comment
-------- | -----
[idapython_docs](https://www.hex-rays.com/products/ida/support/idapython_docs/)| idapython official docs. 
[GenCallPath](GenCallPath) | Generate the function call path. Include static path and dynamic path. 

# 3. Plugins on github
name     | comment
-------- | -----
[keypatch](https://github.com/keystone-engine/keypatch) | Modify the program.  
[findcrypt](https://github.com/polymorf/findcrypt-yara) | Find encryption algorithm.  
[Ponce](https://github.com/illera88/Ponce) | Plugins of symbol execution, No.1 in 2016 IDA plug-in competition.  
[ida_ipython](https://github.com/james91b/ida_ipython) | Embedded ipython.  
[IDAmetrics](https://github.com/mxmssh/IDAmetrics) | Improving fuzzing using software complexity metrics.

# 4. IDA in Ubuntu
```shell
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6-i686:i386 libexpat1:i386 libffi6:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libice6:i386 libpcre3:i386 libpng12-0:i386 libsm6:i386 libstdc++6:i386 libuuid1:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxrender1:i386 zlib1g:i386 libx11-xcb1:i386 libdbus-1-3:i386 libxi6:i386 libsm6:i386 libcurl3:i386 
```
tmux error `Without libcurses can work only with xterm/linux`
`env TERM=xterm /path/to/idal`