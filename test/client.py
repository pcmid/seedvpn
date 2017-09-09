#!/usr/bin/env python3
# coding=utf-8
# pylint: disable=W0603
import os
import sys
import socket
import select
import logging
import time


def client_run():  # pylint: disable=R0912,R0915
    '''运行'''
    logged = False
    try_logins = 5
    log_time = 0
    global IFACE_IP, PORT, PASSWORD  # pylint: disable=W0603
    pc = AES_Encrypt(PASSWORD)  # pylint: disable=C0103
    udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server_ip = socket.gethostbyname(IFACE_IP)
    udpfd.bind(("", 0))

    while True:  # pylint: disable=R1702
        if not logged and time.time() - log_time > 2:

            logging.info("登录中...")
            # logging.debug("密码 " + PASSWORD)
            udpfd.sendto(
                pc.encrypt(("LOGIN:" + PASSWORD).encode()),
                (server_ip, PORT))
            # logging.debug("客户端登录数据: %s" %
            #              (len(pc.encrypt(("LOGIN:" + PASSWORD).encode()))))
            try_logins -= 1
            if try_logins == 0:
                logging.error("连接失败")
                sys.exit(LOGIN_TIMEOUT)
            log_time = time.time()

        rset = select.select([udpfd, tfd], [], [], 1)[0]
        for r in rset:  # pylint: disable=C0103
            if r == tfd:
                data = os.read(tfd, MTU)
                #src_d, dst_d = data[16:20], data[20:24]
                # logging.debug("网卡数据：src: %s \t dst: %s" %
                #              (b2a_hex(src_d), b2a_hex(dst_d)))
                # data_header = data[:64]
                # print("data_header: %s" % (b2a_hex(data_header)))
                # logging.debug("网卡收到长度：%d" % (len(data)))
                # logging.debug("客户端发送长度: %s" % (len(pc.encrypt(data))))
                udpfd.sendto(pc.encrypt(data), (
                    server_ip, PORT))

            elif r == udpfd:
                data, src = udpfd.recvfrom(BUFFER_SIZE)
                # logging.debug("解密前的数据: %s" % (data))
                data = pc.decrypt(data)
                # logging.debug("socket收到数据 %s" % (data))
                try:
                    data = data.decode()
                    if data.startswith("LOGIN"):
                        if data.endswith("PASSWORD"):
                            logged = False
                            logging.error("连接失败！")
                        elif data.split(":")[1] == (
                                "SUCCESS"):
                            recv_ip = data.split(":")[2]
                            logged = True
                            try_logins = 5
                            logging.info("登录成功\tIP: %s", recv_ip)
                            config(recv_ip)
                            config_routes()
                except UnicodeDecodeError:
                    # logging.debug("套接字收到数据 %s" %(data))
                    # logging.debug("客户端写入网卡长度: %s" % (len(data)))
                    os.write(tfd, data)
                except AttributeError:
                    logging.warning("抓到一个str：%s", data)
                except:
                    raise Exception
