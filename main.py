#!/usr/bin/env python3

'''
    A Light UDP Tunnel VPN
    Author: sweet-st
    Updated: 2017-08-22
'''

import os
import sys
import hashlib
import getopt
import fcntl
import time
import struct
import socket
import select
import traceback
import signal
import ctypes
import binascii

SHARED_PASSWORD = hashlib.sha1("test").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

BUFFER_SIZE = 8192
MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1/24"
MTU = 1500
TIMEOUT = 60*10 # seconds

class Tunnel():
    def create(self):
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
        self.tname = ifs[:16].strip("\x00")

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print("Configuring interface %s with ip %s" % (self.tname, ip))
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))

    def config_routes(self):
        if MODE == 1: # Server
            pass
        else: # Client
            print("Setting up new gateway ...")
            # Look for default route
            routes = os.popen("ip route show").readlines()
            defaults = [x.rstrip() for x in routes if x.startswith("default")]
            if not defaults:
                raise Exception("Default route not found, maybe not connected!")
            self.prev_gateway = defaults[0]
            self.prev_gateway_metric = self.prev_gateway + " metric 2"
            self.new_gateway = "default dev %s metric 1" % (self.tname)
            self.tun_gateway = self.prev_gateway.replace("default", IP)
            with open("/etc/resolv.conf", "rb") as fs:
                self.old_dns = fs.read()
            # Remove default gateway
            os.system("ip route del " + self.prev_gateway)
            # Add default gateway with metric
            os.system("ip route add " + self.prev_gateway_metric)
            # Add exception for server
            os.system("ip route add " + self.tun_gateway)
            # Add new default gateway
            os.system("ip route add " + self.new_gateway)
            # Set new DNS to 8.8.8.8
            with open("/etc/resolv.conf", "wb") as fs:
                fs.write("nameserver 8.8.8.8")

    def restore_routes(self):
        if MODE == 1: # Server
            pass
        else: # Client
            print("Restoring previous gateway ...")
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
                print("Do login ...")
                self.udpfd.sendto("LOGIN:" + SHARED_PASSWORD + ":" +
                    IFACE_IP.split("/")[0], (IP, PORT))
                self.try_logins -= 1
                if self.try_logins == 0:
                    raise Exception("Failed to log in server.")
                self.log_time = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    if DEBUG: os.write(1, ">")
                    data = os.read(self.tfd, MTU)
                    if MODE == 1: # Server
                        src, dst = data[16:20], data[20:24]
                        for key in self.clients:
                            if dst == self.clients[key]["localIPn"]:
                                self.udpfd.sendto(data, key)
                        # Remove timeout clients
                        curTime = time.time()
                        for key in self.clients.keys():
                            if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                                print("Remove timeout client", key)
                                del self.clients[key]
                    else: # Client
                        self.udpfd.sendto(data, (IP, PORT))
                elif r == self.udpfd:
                    if DEBUG: os.write(1, "<")
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if MODE == 1: # Server
                        key = src
                        if key not in self.clients:
                            # New client comes
                            try:
                                if data.startswith("LOGIN:") and data.split(":")[1]==SHARED_PASSWORD:
                                    localIP = data.split(":")[2]
                                    self.clients[key] = {"aliveTime": time.time(),
                                                        "localIPn": socket.inet_aton(localIP)}
                                    print("New Client from", src, "request IP", localIP)
                                    self.udpfd.sendto("LOGIN:SUCCESS", src)
                            except:
                                print("Need valid password from", src)
                                self.udpfd.sendto("LOGIN:PASSWORD", src)
                        else:
                            # Simply write the packet to local or forward them to other clients ???
                            os.write(self.tfd, data)
                            self.clients[key]["aliveTime"] = time.time()
                    else: # Client
                        if data.startswith("LOGIN"):
                            if data.endswith("PASSWORD"):
                                self.logged = False
                                print("Need password to login!")
                            elif data.endswith("SUCCESS"):
                                self.logged = True
                                self.try_logins = 5
                                print("Logged in server succefully!")
                        else:
                            os.write(self.tfd, data)

def usage(status = 0):
    print("Usage: %s [-s port|-c serverip] [-hd] [-l localip]" % (sys.argv[0]))
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught!")

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:hd")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-d":
            DEBUG += 1
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
        usage(1)

    tun = Tunnel()
    tun.create()
    tun.config(IFACE_IP)
    signal.signal(signal.SIGTERM, on_exit)
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