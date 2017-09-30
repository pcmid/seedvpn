# 十一回家重构咯~

# seedvpn

## 一个udp VPN

服务端 
```Bash
python3 main.py --config server.conf
```

客户端
```Bash
python3 main.py --config client.conf
```

`目前采用AES-128加密`

### TODO

* 客户端的心跳包以及重连
* 握手用aes加密，数据用rsa加密
* 更改deamon的处理方式
* 采用压缩
* etc.

### 配置文件

服务端：
```Bash
[server]                            # 指定此配置文件为服务端
tun_IFACE = 10.10.0.1/24            # 虚拟网卡IP段
port = 1198                         # 服务监听端口
password = qwert                    # 密码
```

客户端
```Bash
[client]                            # 指定此配置文件为客户端
addr = 127.0.0.1                    # 服务器ip地址
port = 1198                         # 服务器监听端口
password = qwert                    # 密码
```
