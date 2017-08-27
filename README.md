seedvpn
=======

一个udp VPN
----------

服务端 
```Bash
python3 main.py --config server.conf
```

客户端
```Bash
python3 main.py --config client.conf
```

`目前采用AES-128加密`

# 配置文件

服务端：

[server] \t\t\t\t\t# 指定此配置文件为服务端

tun_IFACE = 10.10.0.1/24 \t\t\t# 虚拟网卡IP段

port = 1198 \t\t\t\t\t\# 服务监听端口

password = qwert \t\t\t\t\t# 密码

客户端

[client]                            # 指定此配置文件为客户端

addr = 127.0.0.1                    # 服务器ip地址

port = 1198                         # 服务器监听端口

password = qwert                    # 密码
