import os
import sys
import socket
import select
import fcntl
import struct


TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001


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
    print("配置网卡%s ip: %s" % (self.tname, ip))
    os.system("ip link set %s up" % (self.tname))
    os.system("ip link set %s mtu 1000" % (self.tname))
    os.system("ip addr add %s dev %s" % (ip, self.tname))


def configRoutes(self):
    print("设置新路由...")
    # 查找默认路由
    routes = os.popen("ip route show").readlines()
    defaults = [x.rstrip() for x in routes if x.startswith("default")]
    if not defaults:
        print("找不到默认路由，没有网络链接！")
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
