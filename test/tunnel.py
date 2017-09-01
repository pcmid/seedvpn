#!/usr/bin/env python3
# coding=utf-8
# pylint: disable=W0603
'''关于网卡的模块'''


import os
import sys
import fcntl
import struct
import logging


TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001

NETWORK_ERROR = 2

TUN_FD = None
TUN_NAME = None
PREV_GATEWAY = None
PREV_GATEWAY_METRIC = None
NEW_GATEWAY = None
TUN_GATEWAY = None
OLD_DNS = None
TUN_IP = "10.11.0.1/24"
MTU = 1000

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S %a, %d %b %Y')


def create():
    '''创建网卡'''
    global TUN_FD, TUN_NAME
    try:
        TUN_FD = os.open("/dev/net/tun", os.O_RDWR)
    except NameError:
        TUN_FD = os.open("/dev/tun", os.O_RDWR)
    ifs = fcntl.ioctl(TUN_FD, TUNSETIFF, struct.pack(
        "16sH", "tun%d".encode("utf-8"), IFF_TUN))
    dev, _ = struct.unpack("16sH", ifs)
    TUN_NAME = dev.strip(b"\x00").decode()


def close():
    '''关闭网卡套接字'''
    global TUN_FD
    os.close(TUN_FD)


def config(ip=TUN_IP):  # pylint: disable=C0103
    '''配置网卡信息'''
    global TUN_NAME, MTU
    os.system("ip link set %s up" % (TUN_NAME))
    logging.info("ip link set %s up", TUN_NAME)
    os.system("ip link set %s mtu %s" % (TUN_NAME, MTU))
    logging.info("ip link set %s mtu %s", TUN_NAME, MTU)
    os.system("ip addr add %s dev %s" % (ip, TUN_NAME))
    logging.info("ip addr add %s dev %s", ip, TUN_NAME)


def config_routes(server_ip=TUN_IP.strip("/")[0]):
    '''配置路由和设置DNS'''
    global PREV_GATEWAY, NEW_GATEWAY, TUN_GATEWAY, PREV_GATEWAY_METRIC, OLD_DNS
    logging.info("设置新路由...")
    # 查找默认路由
    routes = os.popen("ip route show").readlines()
    defaults = [x.rstrip() for x in routes if x.startswith("default")]
    if not defaults:
        logging.error("找不到默认路由，没有网络链接！")
        sys.exit(NETWORK_ERROR)

    PREV_GATEWAY = defaults[0]
    PREV_GATEWAY_METRIC = PREV_GATEWAY + " metric 2"
    NEW_GATEWAY = "default dev %s metric 1" % (TUN_NAME)
    TUN_GATEWAY = PREV_GATEWAY.replace(
        "default", server_ip)
    with open("/etc/resolv.conf", "rb") as fs:  # pylint: disable=C0103
        OLD_DNS = fs.read()
    # 删除默认路由
    os.system("ip route del " + PREV_GATEWAY)
    logging.info("ip route del " + PREV_GATEWAY)
    # 降低源路由metric等级
    os.system("ip route add " + PREV_GATEWAY_METRIC)
    # 为连接服务器添加的路由
    logging.info("ip route add " + TUN_GATEWAY)
    os.system("ip route add " + TUN_GATEWAY)
    # 添加默认路由
    logging.info("ip route add " + NEW_GATEWAY)
    os.system("ip route add " + NEW_GATEWAY)
    # DNS
    with open("/etc/resolv.conf", "w") as fs:  # pylint: disable=C0103
        fs.write("nameserver 8.8.8.8")
    logging.info("设置完成")


def restore_routes():
    '''恢复原来的路由'''
    global PREV_GATEWAY, NEW_GATEWAY, TUN_GATEWAY, PREV_GATEWAY_METRIC, OLD_DNS
    logging.info("恢复源路由...")
    os.system("ip route del " + NEW_GATEWAY)
    logging.info("ip route del " + NEW_GATEWAY)
    os.system("ip route del " + PREV_GATEWAY_METRIC)
    logging.info("ip route del " + PREV_GATEWAY_METRIC)
    os.system("ip route del " + TUN_GATEWAY)
    logging.info("ip route add " + PREV_GATEWAY)
    os.system("ip route add " + PREV_GATEWAY)
    with open("/etc/resolv.conf", "wb") as fs:  # pylint: disable=C0103
        fs.write(OLD_DNS)
    logging.info("恢复完成")


if __name__ == "__main__":
    create()
    config()
    config_routes()
    while True:
        pass
    restore_routes()
    print("end")
