# X.509Reader

解析X.509证书(Base64)信息

## Usage

设置环境

```c++
// main.cpp
// Linux
#define isLinux true
// Windows
#define isLinux false
```

编译

```bash
$ g++ ./main.cpp ./x509.cpp -fexec-charset=GBK -std=c++11
```

运行

```bash
# 标准输入
$ cat ./xxx.cer | ./x509
# 文件输入
$ ./x509 ./xxx.cer
```

PS: Windows 下运行部分终端可能会有中文编码问题，建议在Linux下运行
