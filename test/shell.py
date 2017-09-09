#!/usr/bin/env python3
# coding=utf-8

import sys
import os
import logging
import getopt
import configparser


ARGS_ERROR = 1


def usage(status):
    '''使用说明'''
    print("Usage: %s [-h] --config config path\n\n" % (sys.argv[0]))
    print(status)
    sys.exit(status)


def __get_option():
    try:
        opts, _ = getopt.getopt(sys.argv[1:], "h", "config=")
    except getopt.GetoptError:
        logging.error("必须指定 --config参数")
    for name, value in opts:
        if name == "-h":
            usage(0)
            sys.exit()
        if name == "--config":
            config_path = value
            return config_path


def __check_config_path(config_path):
    if not os.path.exists(config_path):
        logging.error("找不到配置文件！！！")
        sys.exit()
    else:
        logging.info("检测到配置：" + os.path.abspath(config_path))
        return 0


def parser_config():
    '''解析conf文件
    return：
        client：服务器IP和port,密码
        server：tun's ip port，密码
    '''
    config_path = __get_option()
    __check_config_path(config_path)
    try:
        open(config_path, "r")
    except IOError as e:  # pylint: disable=C0103
        print(e.strerror)
        sys.exit(e.errno)

    config = configparser.ConfigParser()  # pylint: disable=W0621
    # I will take it to other file
    config.read(config_path)

    config_dic = {}
    secs = config.sections()
    if ("client" in secs and "server" in secs) or \
            ("client" not in secs and "server" not in secs):
        raise Exception("配置文件错误：配置只能选择client或server")

    if "server" in secs:
        config_dic["tun_IFACE"] = config.get(
            "server", "tun_IFACE")  # pylint: disable=C0103
        config_dic["port"] = int(config.get("server", "port"))
        config_dic["password"] = config.get("server", "password")
        return config_dic

    if "client" in secs:
        config_dic["addr"] = config.get("client", "addr")
        config_dic["port"] = int(config.get("client", "port"))
        config_dic["password"] = config.get("client", "password")
        return config_dic


if __name__ == "__main__":
    parser_config()
    print(parser_config())
    print("end")
