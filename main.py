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
import logging
import configparser
from copy import deepcopy
import rsa
from IPy import IP
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import daemon

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

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S %a, %d %b %Y')


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
        os.system("ip link set %s up" % (self.tname))
        logging.info("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        logging.info("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
        logging.info("ip addr add %s dev %s" % (ip, self.tname))

    def configRoutes(self):
        logging.info("设置新路由...")
        # 查找默认路由
        routes = os.popen("ip route show").readlines()
        defaults = [x.rstrip() for x in routes if x.startswith("default")]
        if not defaults:
            logging.error("找不到默认路由，没有网络链接！")
            sys.exit(NETWORK_ERROR)

        self.prev_gateway = defaults[0]
        self.prev_gateway_metric = self.prev_gateway + " metric 2"
        self.new_gateway = "default dev %s metric 1" % (self.tname)
        self.tun_gateway = self.prev_gateway.replace(
            "default", self.server_ip)
        with open("/etc/resolv.conf", "rb") as fs:
            self.old_dns = fs.read()
        # 删除默认路由
        os.system("ip route del " + self.prev_gateway)
        logging.info("ip route del " + self.prev_gateway)
        # 降低源路由metric等级
        os.system("ip route add " + self.prev_gateway_metric)
        # 为连接服务器添加的路由
        logging.info("ip route add " + self.tun_gateway)
        os.system("ip route add " + self.tun_gateway)
        # 添加默认路由
        logging.info("ip route add " + self.new_gateway)
        os.system("ip route add " + self.new_gateway)
        # DNS
        with open("/etc/resolv.conf", "w") as fs:
            fs.write("nameserver 8.8.8.8")
        logging.info("设置完成")

    def restoreRoutes(self):
        if not is_server:
            logging.info("恢复源路由...")
            os.system("ip route del " + self.new_gateway)
            logging.info("ip route del " + self.new_gateway)
            os.system("ip route del " + self.prev_gateway_metric)
            logging.info("ip route del " + self.prev_gateway_metric)
            os.system("ip route del " + self.tun_gateway)
            logging.info("ip route add " + self.prev_gateway)
            os.system("ip route add " + self.prev_gateway)
            with open("/etc/resolv.conf", "wb") as fs:
                fs.write(self.old_dns)
            logging.info("恢复完成")

    def run(self):
        global IFACE_IP, PORT, PASSWORD
        pc = AES_Encrypt(PASSWORD)
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if is_server:
            self.config(IFACE_IP)
            self.udpfd.bind(("", PORT))
            logging.info("DHCP...")
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

                logging.info("登录中...")
                logging.debug("密码" + PASSWORD)
                self.udpfd.sendto(
                    pc.encrypt("LOGIN:" + PASSWORD), (self.server_ip, PORT))
                self.tryLogins -= 1
                if self.tryLogins == 0:
                    logging.warning("连接失败")
                self.logTime = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    data = str(pc.decrypt(data))
                    if is_server and (data != "-1"):  # Server
                        src, dst = data[16:20], data[20:24]
                        for key in self.clients:
                            if dst == self.clients[key]["localIPn"]:
                                self.udpfd.sendto(pc.encrypt(data), key)
                    elif data != "-1":  # Client
                        self.udpfd.sendto(pc.encrypt(data), (
                            self.server_ip, PORT))
                    else:
                        pass
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    data = pc.decrypt(data)
                    logging.debug("收到数据 %s" % (data))
                    if is_server:  # Server
                        key = src
                        if key not in self.clients:
                            # 如果第一次连接
                            try:
                                if (data.startswith("LOGIN:") and
                                    data.split(":")[1]) == \
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
                                    #logging.info("新连接：", src, "IP：", localIP)
                                    logging.info("新连接：%s  IP：%s"
                                                 % (src, localIP))
                                    self.udpfd.sendto(
                                        pc.encrypt("LOGIN:SUCCESS" +
                                                   ":" +
                                                   localIP +
                                                   "/" +
                                                   IFACE_IP.split("/")[1]),
                                        src)
                            except:
                                logging.info("来自 %s 的连接密码无效" % (src,))
                                self.udpfd.sendto(
                                    pc.encrypt("LOGIN:PASSWORD"), src)
                        else:
                            os.write(self.tfd, pc.encrypt(data))
                            self.clients[key]["aliveTime"] = time.time()

                    else:  # Client
                        try:
                            if data.startswith("LOGIN"):
                                if data.endswith("PASSWORD"):
                                    self.logged = False
                                    logging.error("连接失败！")
                                elif data.split(":")[1] == (
                                        "SUCCESS"):
                                    recvIP = data.split(":")[2]
                                    self.logged = True
                                    self.tryLogins = 5
                                    logging.info("登录成功\nIP: %s" % (recvIP,))
                                    self.config(recvIP)
                                    self.configRoutes()
                        except:
                            os.write(self.tfd, pc.encrypt(data))
            if is_server:  # Server
                # 删除timeout的连接
                curTime = time.time()
                clientsCopy = deepcopy(self.clients)
                for key in clientsCopy:
                    if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                        logging.info("删除超时连接：%s" % (key,))
                        logging.info("回收ip %s" %
                                     (self.clients[key]["localIP"]))
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


class RSA_Encrypt(object):
    '''加密和解密数据'''

    def __init__(self):
        if is_server:
            pass

        else:
            pass

    def encrypt(self, data):
        '''返回加密的密文'''
        pass

    def dencrypt(self, data):
        '''返回解密的数据'''
        pass


class AES_Encrypt(object):
    def __init__(self, key):
        count = len(key)
        if count < 16:
            add = (16 - count)
            #\0 backspace
            self.key = key + ('\0' * add)
        elif count > 16 and count < 32:
            add = (32 - count)
            self.key = key + ('\0' * add)
        else:
            logging.error("密码太长")
            sys.exit(PASSWD_ERROR)
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0' * 16)
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 为了兼顾效率和安全性，采用AES-128
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length - (count % length))
            text = text + ('\0' * add)
        #print("加密" + str(len(text)))
        if len(text) % 16 == 0:
            self.ciphertext = cryptor.encrypt(text)
            return self.ciphertext
        else:
            logging.debug("加密无效")
            return "-1"

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0' * 16)
        #print("解密" + str(len(text)))
        if len(text) % 16 == 0:
            plain_text = cryptor.decrypt(text)
            return plain_text.rstrip(b'\0').decode()
        else:
            logging.debug("解密无效")
            return "-1"


def ping_server():
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
        pwd = config.get("server", "password")
        return tun_IFACE, int(port), pwd

    if "client" in secs:
        is_server = 0
        addr = config.get("client", "addr")
        port = config.get("client", "port")
        pwd = config.get("client", "password")
        return addr, int(port), pwd


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
        logging.error("必须指定 --config参数")
        usage(ARGS_ERROR)

    IFACE_IP, PORT, PASSWORD = parserConfig(config)
    # if is_server:
    #    daemon.daemon()
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
