#!/usr/bin/env python3
# coding=utf-8
'''客户端'''
import socket
import select
import logging
import time

import shell
import tunnel
import hander


def client_main():
    config = shell.get_config()
    # config["addr"]
    # config["port"]
    # config["password"]

    tunfd = tunnel.create()

    logged = False
    try_logins = 5
    log_time = 0

    udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_ip = socket.gethostbyname(config["addr"])
    udpfd.bind(("", 0))
    # handing
    hander = hander.Hander(False, config)
    for i in range(4):
        if not logged and time.time() - log_time > 2:
            logging.info("login to ", server_ip)
            recv_ip = hander.login()
            if not recv_ip: # login error
                logging.error("loggin error")
                continue
            else:
                logging.info("login success")
    # send public key
    hander.send_public_key()
    while True:
