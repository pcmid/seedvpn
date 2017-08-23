#!/usr/bin/env python3

'''
    A Light UDP Tunnel VPN
    Author: sweet-st
    Updated: 2017-08-22
'''

import os
import sys
import getopt
import fcntl
import time
import struct
import socket
import select
import traceback
from copy import deepcopy

PASSWORD = "test"
ARGS_ERROR = 1
NETWORK_ERROR = 2
PASSWD_ERROR = 3

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

BUFFER_SIZE = 8192
MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1/24"
MTU = 1500
TIMEOUT = 10 # seconds

class Tunnel():
    def create(self):
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d".encode("utf-8"), IFF_TUN))
        #self.tname = ifs.strip(b'\x00')
        dev, _ = struct.unpack("16sH", ifs)
        #dev = dev.decode()
        self.tname = dev.strip(b"\x00").decode()

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print("配置网卡%s ip: %s" % (self.tname, ip))
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))

    def config_routes(self):
        if MODE == 1: # Server
            pass
        else: # Client
            print("设置新网关...")
            # 查找默认路由
            routes = os.popen("ip route show").readlines()
            defaults = [x.rstrip() for x in routes if x.startswith("default")]
            if not defaults:
                print("找不到默认路由，没有网络链接！")
                sys.exit(NETWORK_ERROR)
            self.prev_gateway = defaults[0]
            self.prev_gateway_metric = self.prev_gateway + " metric 2"
            self.new_gateway = "default dev %s metric 1" % (self.tname)
            self.tun_gateway = self.prev_gateway.replace("default", IP)
            with open("/etc/resolv.conf", "rb") as fs:
                self.old_dns = fs.read()
            # 删除默认路由
            os.system("ip route del " + self.prev_gateway)
            # 降低源路由metric等级
            os.system("ip route add " + self.prev_gateway_metric)
            # 为连接服务器添加的路由
            os.system("ip route add " + self.tun_gateway)
            # 添加默认路由
            os.system("ip route add " + self.new_gateway)
            # DNS
            with open("/etc/resolv.conf", "w") as fs:
                fs.write("nameserver 8.8.8.8")

    def restore_routes(self):
        if MODE == 1: # Server
            pass
        else: # Client
            print("恢复源路由...")
            os.system("ip route del " + self.new_gateway)
            os.system("ip route del " + self.prev_gateway_metric)
            os.system("ip route del " + self.tun_gateway)
            os.system("ip route add " + self.prev_gateway)
            with open("/etc/resolv.conf", "wb") as fs:
                fs.write(self.old_dns)

    def run(self):
        global PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if MODE == 1:
            self.udpfd.bind(("", PORT))
        else:
            self.udpfd.bind(("", 0))

        self.clients = {}
        self.logged = False
        self.try_logins = 5
        self.log_time = 0

        while True:
            if MODE == 2 and not self.logged and time.time() - self.log_time > 2.:
                print("登录中...")
                self.udpfd.sendto(("LOGIN:" + PASSWORD + ":" +
                    IFACE_IP.split("/")[0]).encode(), (IP, PORT))
                self.try_logins -= 1
                if self.try_logins == 0:
                    raise Exception("登录失败")
                self.log_time = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    if MODE == 1: # Server
                        src, dst = data[16:20], data[20:24]
                        for key in self.clients:
                            if dst == self.clients[key]["localIPn"]:
                                self.udpfd.sendto(data, key)
                    else: # Client
                        self.udpfd.sendto(data, (IP, PORT))
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if MODE == 1: # Server
                        key = src
                        if key not in self.clients:
                            try:
                                if (data.decode().startswith("LOGIN:") and data.decode().split(":")[1])==PASSWORD:
                                    localIP = data.decode().split(":")[2]
                                    self.clients[key] = {"aliveTime": time.time(),
                                                        "localIPn": socket.inet_aton(localIP)}
                                    print("新连接：", src, "IP：", localIP)
                                    self.udpfd.sendto("LOGIN:SUCCESS".encode(), src)
                            except:
                                print("来自",src,"的连接密码无效")
                                self.udpfd.sendto("LOGIN:PASSWORD".encode(), src)
                        else:
                            os.write(self.tfd, data)
                            self.clients[key]["aliveTime"] = time.time()
                    else: # Client
                        if data.decode().startswith("LOGIN"):
                            if data.decode().endswith("PASSWORD"):
                                self.logged = False
                                raise Exception("登录密码错误！")

                            elif data.decode().endswith("SUCCESS"):
                                self.logged = True
                                self.try_logins = 5
                                print("登录成功")
                        else:
                            os.write(self.tfd, data)
            # 删除timeout的连接
            curTime = time.time()
            clients_copy = deepcopy(self.clients)
            for key in clients_copy:
                if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                    print("删除超时连接：", key)
                    self.clients.pop(key)

def usage(status = ARGS_ERROR):
    print("Usage: %s [-s port|-c serverip] [-h] [-l localip]" % (sys.argv[0]))
    sys.exit(status)


if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:hd")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-s":
            MODE = 1
            PORT = int(optarg)
        elif opt == "-c":
            MODE = 2
            IP, PORT = optarg.split(",")
            IP = socket.gethostbyname(IP)
            PORT = int(PORT)
        elif opt == "-l":
            IFACE_IP = optarg

    if MODE == 0 or PORT == 0:
        usage(0)

    tun = Tunnel()
    tun.create()
    tun.config(IFACE_IP)
    tun.config_routes()
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print(traceback.format_exc())
    finally:
        tun.restore_routes()
        tun.close()
        print("\nend")