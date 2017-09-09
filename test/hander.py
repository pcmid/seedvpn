import socket
import logging
import AES_Encrypt
import shell

'''
    class Hander():
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port
            self.fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def login():
            pass
'''


class Hander():
    def __init__(self, IS_SERVER, config_dictionary):
        if not IS_SERVER:
            self.IS_SERVER = False
            self.ip = config_dictionary["addr"]
            self.port = config_dictionary["port"]
            self.password = config_dictionary["password"]
        else:
            self.IS_SERVER = True
            self.password = config_dictionary["password"]

        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def login(self):
        data = "LOGIN:" + self.password + ":" + "tihs is random message"
        en_data = AES_Encrypt.encrypt(data)
        self.udpfd.sendto(en_data, (self.ip, self.port))

    def check_loggin(self, data, log_times):
        de_data = AES_Encrypt.decrypt(data)
        try:
            de_data = de_data.decode()
        except:
            logging.debug("check login decode error")
            return None
        # success de_data : LOGIN:SUCCESS:10.10.0.2
        # error   de_data : LOGIN:PASSWORD
        if de_data.startswith("LOGIN:SUCCESS"):
            recv_ip = de_data.split(":")[2]
            return recv_ip
        else:
            return 1  # login error

    def check_passwd(self, data):
        de_data = AES_Encrypt.decrypt(data)
        try:
            de_data = de_data.decode()
        except UnicodeDecodeError:
            logging.debug("de_data decode error")
            return 1  # passwd decode error

        if (data.startswith("LOGIN:") and data.split(":")[1]) == self.password:
            return 0  # password right
        else:
            return 2  # password error

    def send_public_key(self, ip, port):
        if self.IS_SERVER:
            ip = ip
            port = port
        else:
            ip = self.ip
            port = self.port

        with open("public.pem", 'r') as public_pem:
            public_key = public_pem.read()

        en_public_key = AES_Encrypt.encrypt(public_key)
        self.udpfd.sendto(en_public_key, (ip, port))
