# MUD - MPUDP - MultiPath UDP

MUD is a secure, multipath network protocol over UDP.
See [glorytun](https://github.com/angt/glorytun) for details.

### 项目配置

- 此项目含有子模块，需要加上 `--recursive`参数

```bash
$ git clone git@github.com:jun0377/my_mud.git --recursive
```

- 需要安装 `libsodium-dev`,ubuntu上安装命令如下

```bash
$ sudo apt-get install libsodium-dev
```

- 编译,直接执行 `make`即可

```bash
jun@ubuntu:my_mud$ make
cc -Wall -O2 -o test test.c -lsodium
```

### 测试

- `test.c`测试程序只能用来测试client/server的连通性，并没有提供多路径传输的测试例程，需要手动实现
- `test.c`中使用`INADDR_LOOPBACK`进行测试，导致只能在同一台设备上进行测试
- 运行server端
```bash
$ ./test
```
- 运行client端
```bash
./test abcdef
```


### Compatibility

Linux is the platform of choice but it was successfully ported to OpenBSD and OSX.

### Dependencies

* A recent version of GCC or Clang.
* [libsodium](https://github.com/jedisct1/libsodium).

### Security

Encryption and authentication is done with AEGIS256 when aesni is available otherwise ChaCha20-Poly1305 is used.
The Diffie-Hellman function X25519 is used for key exchange.

### Issues

For feature requests and bug reports, please create an [issue](https://github.com/angt/mud/issues).
