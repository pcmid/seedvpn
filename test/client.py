import os
import sys
import socket
import select


def main():
    def run(self):
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_ip = socket.gethostbyname(IFACE_IP)
        self.udpfd.bind(("", 0))

        self.clients = {}
        self.logged = False
        self.tryLogins = 5
        self.logTime = 0
        while True:
            if not self.logged and time.time() - self.logTime > 2:
                print("登录中...")
                print(type(("LOGIN:" + PASSWORD).encode()))
                print(PORT)
                self.udpfd.sendto(
                    ("LOGIN:" + PASSWORD).encode(), (self.server_ip, PORT))
                self.tryLogins -= 1
                if self.tryLogins == 0:
                    print("登录失败")
                    sys.exit(LOGIN_TIMEOUT)
                self.logTime = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    self.udpfd.sendto(data, (self.server_ip, PORT))
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    try:
                        if data.decode().startswith("LOGIN"):
                            if data.decode().endswith("PASSWORD"):
                                self.logged = False
                                print("登录密码错误！")
                                sys.exit(PASSWD_ERROR)

                            elif data.decode().split(":")[1] == (
                                    "SUCCESS"):
                                recvIP = data.decode().split(":")[2]
                                self.logged = True
                                self.tryLogins = 5
                                print(recvIP + "登录成功")
                                self.config(recvIP)
                                self.configRoutes()
                    except:
                        os.write(self.tfd, data)
