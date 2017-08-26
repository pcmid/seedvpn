import os
import sys
import socket
import select
import tunnel


def main():
    def run_server(self):
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.config(IFACE_IP)
        self.udpfd.bind(("", PORT))
        print("DHCP...")
        dhcpd = DHCP(IFACE_IP.replace('1/', '0/'))

        self.clients = {}
        self.logged = False
        self.tryLogins = 5
        self.logTime = 0
        while True:
            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    src, dst = data[16:20], data[20:24]
                    for key in self.clients:
                        if dst == self.clients[key]["localIPn"]:
                            self.udpfd.sendto(data, key)
                    
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
                                         IFACE_IP.split("/")[1] +
                                         "/" +
                                         ).encode(),
                                        src)
                            except:
                                print("来自", src, "的连接密码无效")
                                self.udpfd.sendto(
                                    "LOGIN:PASSWORD".encode(), src)
                        else:
                            os.write(self.tfd, data)
                            self.clients[key]["aliveTime"] = time.time()

            # 删除timeout的连接
            curTime = time.time()
            clientsCopy = deepcopy(self.clients)
            for key in clientsCopy:
                if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                    print("删除超时连接：", key)
                    print("回收ip", self.clients[key]["localIP"])
                    dhcpd.removeUsedIP(self.clients[key]["localIP"])
                    self.clients.pop(key)
