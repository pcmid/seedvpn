#!/usr/bin/env python3
# coding=utf-8

#           seedvpn  Copyright (C) 2017  sweet-st
# This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
# This is free software, and you are welcome to redistribute it
# under certain conditions; type `show c' for details.
#
# The hypothetical commands `show w' and `show c' should show the appropriate
# parts of the General Public License.  Of course, your program's commands
# might be different; for a GUI interface, you would use an "about box".
#
#  You should also get your employer (if you work as a programmer) or school,
# if any, to sign a "copyright disclaimer" for the program, if necessary.
# For more information on this, and how to apply and follow the GNU GPL, see
#<http://www.gnu.org/licenses/>.
#
#  The GNU General Public License does not permit incorporating your program
# into proprietary programs.  If your program is a subroutine library, you
# may consider it more useful to permit linking proprietary applications with
# the library.  If this is what you want to do, use the GNU Lesser General
# Public License instead of this License.  But first, please read
#<http://www.gnu.org/philosophy/why-not-lgpl.html>.


'''
    A Light UDP Tunnel VPN
    Author: sweet-st
    Mail: foreverofsweet@gmail.com
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
import rsa
import configparser
from copy import deepcopy
from IPy import IP
import daemon

PASSWORD = "test"
ARGS_ERROR = 1
NETWORK_ERROR = 2
PASSWD_ERROR = 3
LOGIN_TIMEOUT = 4


TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001


BUFFER_SIZE = 8192
is_server = 2

PORT = 0
IFACE_IP = "10.0.0.1/24"
MTU = 1500
TIMEOUT = 10 * 60  # seconds

def is_set(value):
    try:
        value
    except:
        return None
    return True
class Tunnel(object):

    def create(self):
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack(
            "16sH", "tun%d".encode("utf-8"), IFF_TUN))
        dev, _ = struct.unpack("16sH", ifs)
        self.tname = dev.strip(b"\x00").decode()

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print("ip link set %s up" % (self.tname))
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        print("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
        print("ip addr add %s dev %s" % (ip, self.tname))

    def configRoutes(self):
        print("设置新路由...")
        # 查找默认路由
        routes = os.popen("ip route show").readlines()
        defaults = [x.rstrip() for x in routes if x.startswith("default")]
        if not defaults:
            print("找不到默认路由，没有网络链接！")
            sys.exit(NETWORK_ERROR)
        if is_set(self.prev_gateway):
            self.prev_gateway = defaults[0]
            self.prev_gateway_metric = self.prev_gateway + " metric 2"
            self.new_gateway = "default dev %s metric 1" % (self.tname)
            self.tun_gateway = self.prev_gateway.replace(
                "default", self.server_ip)
            with open("/etc/resolv.conf", "rb") as fs:
                self.old_dns = fs.read()
            # 删除默认路由
            os.system("ip route del " + self.prev_gateway)
            print("ip route del " + self.prev_gateway)
            # 降低源路由metric等级
            os.system("ip route add " + self.prev_gateway_metric)
            # 为连接服务器添加的路由
            print("ip route add " + self.tun_gateway)
            os.system("ip route add " + self.tun_gateway)
            # 添加默认路由
            print("ip route add " + self.new_gateway)
            os.system("ip route add " + self.new_gateway)
            # DNS
            with open("/etc/resolv.conf", "w") as fs:
                fs.write("nameserver 8.8.8.8")
            print("设置完成")
        else:
            print("重新连接...")

    def restoreRoutes(self):
        print("\n恢复源路由...")
        os.system("ip route del " + self.new_gateway)
        print("ip route del " + self.new_gateway)
        os.system("ip route del " + self.prev_gateway_metric)
        print("ip route del " + self.prev_gateway_metric)
        os.system("ip route del " + self.tun_gateway)
        print("ip route add " + self.prev_gateway)
        os.system("ip route add " + self.prev_gateway)
        with open("/etc/resolv.conf", "wb") as fs:
            fs.write(self.old_dns)
        print("恢复完成")

    def run(self):
        global IFACE_IP, PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if is_server:
            self.config(IFACE_IP)
            self.udpfd.bind(("", PORT))
            print("DHCP...")
            dhcpd = DHCP(IFACE_IP.replace('1/', '0/'))
        else:
            self.server_ip = socket.gethostbyname(IFACE_IP)
            self.udpfd.bind(("", 0))

        self.clients = {}
        self.logged = False
        self.tryLogins = 5
        self.logTime = 0
        while True:
            if not is_server and\
                    not self.logged and\
                    time.time() - self.logTime > 2:

                print("登录中...")
                self.udpfd.sendto(
                    ("LOGIN:" + PASSWORD).encode(), (self.server_ip, PORT))
                self.tryLogins -= 1
                if self.tryLogins == 0:
                    print("连接失败")
                self.logTime = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    if is_server:  # Server
                        src, dst = data[16:20], data[20:24]
                        for key in self.clients:
                            if dst == self.clients[key]["localIPn"]:
                                self.udpfd.sendto(data, key)
                    else:  # Client
                        self.udpfd.sendto(data, (self.server_ip, PORT))
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if is_server:  # Server
                        key = src
                        if key not in self.clients:
                            # 如果第一次连接
                            try:
                                if (data.decode().startswith("LOGIN:") and
                                    data.decode().split(":")[1]) == \
                                        PASSWORD:
                                    # localIP = data.decode().split(":")[2]
                                    localIP = dhcpd.assignIP()
                                    self.clients[key] = {"aliveTime":
                                                         time.time(),
                                                         "localIP":
                                                         localIP,
                                                         "localIPn":
                                                         socket.inet_aton(
                                                             localIP)
                                                         }
                                    print("新连接：", src, "IP：", localIP)
                                    self.udpfd.sendto(
                                        ("LOGIN:SUCCESS" +
                                         ":" +
                                         localIP +
                                         "/" +
                                         IFACE_IP.split("/")[1]
                                         ).encode(),
                                        src)
                            except:
                                print("来自", src, "的连接密码无效")
                                self.udpfd.sendto(
                                    "LOGIN:PASSWORD".encode(), src)
                        else:
                            os.write(self.tfd, data)
                            self.clients[key]["aliveTime"] = time.time()

                    else:  # Client
                        try:
                            if data.decode().startswith("LOGIN"):
                                if data.decode().endswith("PASSWORD"):
                                    self.logged = False
                                    print("连接失败！")
                                elif data.decode().split(":")[1] == (
                                        "SUCCESS"):
                                    recvIP = data.decode().split(":")[2]
                                    self.logged = True
                                    self.tryLogins = 5
                                    print("登录成功\n" + "IP: " + recvIP)
                                    self.config(recvIP)
                                    self.configRoutes()
                        except:
                            os.write(self.tfd, data)
            if is_server:  # Server
                # 删除timeout的连接
                curTime = time.time()
                clientsCopy = deepcopy(self.clients)
                for key in clientsCopy:
                    if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                        print("删除超时连接：", key)
                        print("回收ip", self.clients[key]["localIP"])
                        dhcpd.removeUsedIP(self.clients[key]["localIP"])
                        self.clients.pop(key)


class DHCP():
    ''' 分配ip给用户 '''

    def __init__(self, ip):
        self.IPPool = IP(ip)
        # 去掉网关，服务器和广播地址
        self.usedIPList = [self.IPPool[0], self.IPPool[1], self.IPPool[-1]]

    def addUsedIP(self, usdIP):
        self.usedIPList.append(usdIP)

    def removeUsedIP(self, unUsedIP):
        self.usedIPList.remove(IP(unUsedIP))

    def assignIP(self):
        resIP = [ip for ip in self.IPPool if ip not in self.usedIPList][0]
        self.addUsedIP(resIP)
        return resIP.strNormal()


class Encrypt(object):
    '''加密和解密数据'''

    def __init__(self):
        if is_server:
            with open("private.pem", "r") as f:
                privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())

        else:
            with open("public.pem", "r") as f:
                pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())

    def encrypt(self, data):
        '''返回加密的密文'''
        pass

    def dencrypt(self, data):
        '''返回解密的数据'''
        pass


def usage(status):
    print("Usage: %s [-h] --config config path\n\n" % (sys.argv[0]))
    print(status)
    sys.exit(status)


def parserConfig(configPath):
    '''解析conf文件
    return：
        client：服务器IP和port
        server：tun's ip port
    '''
    global is_server
    try:
        open(configPath, "r")
    except IOError as e:
        print(e.strerror)
        sys.exit(e.errno)

    config = configparser.ConfigParser()
    config.read(configPath)

    secs = config.sections()
    if ("client" in secs and "server" in secs) or \
            ("client" not in secs and "server" not in secs):
        raise Exception("配置文件错误：配置只能选择client或server")

    if "server" in secs:
        is_server = 1
        tun_IFACE = config.get("server", "tun_IFACE")
        port = config.get("server", "port")
        key = config.get("server", "key")
        return tun_IFACE, int(port), key

    if "client" in secs:
        is_server = 0
        addr = config.get("client", "addr")
        port = config.get("client", "port")
        key = config.get("client", "key")
        return addr, int(port), key


if __name__ == "__main__":
    try:
        opts, _ = getopt.getopt(sys.argv[1:], "h", "config=")
        for name, value in opts:
            if name == "-h":
                usage(0)
                sys.exit()
            if name == "--config":
                config = value
    except getopt.GetoptError:
        print("必须指定 --config参数")
        usage(ARGS_ERROR)

    IFACE_IP, PORT, KEY = parserConfig(config)
    #daemon.daemon()
    if is_server == 2 or PORT == 0:
        usage(0)

    tun = Tunnel()
    tun.create()
    try:
        tun.run()
    except KeyboardInterrupt:
        try:
            # print(traceback.format_exc())
            tun.restoreRoutes()
            tun.close()
        except:
            pass
    finally:
        print("end")
