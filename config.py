#!/usr/bin/env python3
#coding=utf-8
import configparser
import sys

def parserConfig(configPath):
    '''解析conf文件
    return：
        client：服务器IP和port
        server：tun's ip port
    '''
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

    if "client" in secs:
        addr = config.get("client", "addr")
        port = config.get("client", "port")
        return addr, int(port)

    if "server" in secs:
        tun_IFACE = config.get("server", "tun_IFACE")
        port = config.get("server", "port")
        return tun_IFACE, int(port)
