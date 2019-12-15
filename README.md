# HTTPTASK

- [ ] libevent Mutiple concurrent
- [ ] 解析GET/POST报文，做出相应的响应 
- [ ] UpLoad/DownLoad file
- [ ] chunk transmit /Keep alive /pipe
- [ ] openssl --> https

- 文件目录

```c
├ dict     // 编译好的文件版本放在这里
├ keys     // https
├ src     //  源代码文件放在这里
││http-common.c
││http-common.h
││openSSL.c
││template.c
││utils.h
│└utils.c
├ test    // 测试文件放在这里
│└test.c  // 局部测试文件放在这 
│ readme.md 阅读须知
│ .ignore 本地vscode配置或者自己写的小测试不需要上传到github上的放在这

```

下载文件时注意到文件放到./src/file 文件目录下
