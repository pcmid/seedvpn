#!/usr/bin/env python3
# coding=utf-8

import os
import sys
import socket
import select
from seedvpn import tunnel, DHCP, shell, AES_Encrypt


def server_run():  # pylint: disable=C0111

    config = shell.parser_config()
    AES_Encrypt.get_pwd_from_config(config["pwd"])
    udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpfd.bind(("", ))
    dhcpd = DHCP(IFACE_IP.replace('1/', '0/'))
    logging.info("DHCP启动完成")

    clients = {}
    while True:  # pylint: disable=R1702
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
                if IS_SERVER:  # Server
                    src, dst = data[16:20], data[20:24]
                    # logging.debug("src: %s \t dst: %s" %
                    # (b2a_hex(src), b2a_hex(dst)))
                    for key in clients:
                        if dst == clients[key]["local_ipn"]:
                            # logging.debug("服务端socket写入长度: %s" %
                            #              (len(pc.encrypt(data))))
                            udpfd.sendto(pc.encrypt(data), key)
                else:  # Client
                    # logging.debug("客户端发送长度: %s" % (len(pc.encrypt(data))))
                    udpfd.sendto(pc.encrypt(data), (
                        server_ip, PORT))

            elif r == udpfd:
                data, src = udpfd.recvfrom(BUFFER_SIZE)
                data = pc.decrypt(data)
                # logging.debug("socket收到数据 %s" % (data))
                if key not in clients:
                    # 如果第一次连接
                    try:
                        data = data.decode()
                        if (data.startswith("LOGIN:") and
                                data.split(":")[1]) == \
                                PASSWORD:
                            local_ip = dhcpd.assign_ip()
                            clients[key] = {"aliveTime":
                                                 time.time(),
                                                 "local_ip":
                                                 local_ip,
                                                 "local_ipn":
                                                 socket.inet_aton(
                                                     local_ip)
                                                }
                            logging.info("新连接：%s  IP：%s",
                                         src, local_ip)
                            udpfd.sendto(
                                pc.encrypt(("LOGIN:SUCCESS" +
                                            ":" +
                                            local_ip +
                                            "/" +
                                            IFACE_IP.split("/")[1]
                                           ).encode()),
                                src)
                    except UnicodeDecodeError:
                        logging.warning("来自 %s 的连接密码无效", src)
                        udpfd.sendto(
                            pc.encrypt("LOGIN:PASSWORD".encode()), src)
                    except AttributeError:
                        logging.warning("抓到一个str：%s", data)
                    except:
                        raise Exception
                else:
                    # logging.debug("服务端写入网卡长度: %s" % (len(data)))
                    os.write(tfd, data)
                    #src_d2, dst_d2 = data[16:20], data[20:24]
                    # logging.debug("服务端发出：src: %s \t dst: %s" %
                    #              (b2a_hex(src_d2), b2a_hex(dst_d2)))
                    clients[key]["aliveTime"] = time.time()
            # 删除timeout的连接
            cur_time = time.time()
            clients_copy = deepcopy(clients)
            for key in clients_copy:
                if cur_time - clients[key]["aliveTime"] > TIMEOUT:
                    logging.info("删除超时连接：%s", key)
                    logging.info("回收ip %s",
                                 (clients[key]["local_ip"]))
                    dhcpd.remove_unused_ip_from_list(
                        clients[key]["local_ip"])
                    clients.pop(key)

def main(config_dic):
    global 