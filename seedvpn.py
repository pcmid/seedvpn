import os
import sys
import socket
import struct
import argparse
import fcntl
import select
#import ConfigParser
class tunnel:
    def __init__(self, ip, mask, gw):
        
        # find const values
        # grep IFF_UP -rl /usr/include/
        self.IFF_UP = 0x1
        self.IFF_RUNNING = 0x40
        self.IFNAMSIZ = 16
        self.SIOCSIFADDR = 0x8916
        self.SIOCSIFNETMASK = 0x891c
        self.SIOCGIFFLAGS = 0x8913
        self.SIOCSIFFLAGS = 0x8914
        self.SIOCADDRT = 0x890B

        self.RTF_UP = 0x0001
        self.RTF_GATEWAY = 0x0002

        self.AF_INET = socket.AF_INET

        self.TUNSETIFF = 0x400454ca
        self.TUNSETOWNER = self.TUNSETIFF + 2
        self.IFF_TUN = 0x0001
        self.IFF_NO_PI = 0x1000

        self.ip = ip
        self.mask = mask
        self.gw = gw

    def create_tunnel():

        # Open TUN device file.
        tun = open('/dev/net/tun', 'r+b')

        # Tall it we want a TUN device named tun0.
        ifr = struct.pack('16sH', 'tun%d', IFF_TUN | IFF_NO_PI)
        ret = fcntl.ioctl(tun, TUNSETIFF, ifr)
        dev, _ = struct.unpack('16sH', ret)
        dev = dev.strip()

        # Optionally, we want it be accessed by the normal user.
        fcntl.ioctl(tun, TUNSETOWNER, 1000)
        return dev, tun

    def configure(ip, mask, dev):
        # http://stackoverflow.com/questions/6652384/how-to-set-the-ip-address-from-c-in-linux
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)
        AF_INET = socket.AF_INET
        fd = sock.fileno()
        addrbuf = struct.pack('BBBB', *[int(el) for el in ipaddr.split('.')])
        maskbuf = struct.pack('BBBB', *[int(el) for el in netmask.split('.')])
        sockaddr_mt = '16sHH4s'
        flags_mt = '16sH'

        # ADDR
        siocsifaddr = struct.pack(sockaddr_mt, dev, AF_INET, 0, addrbuf)
        fcntl.ioctl(fd, SIOCSIFADDR, siocsifaddr)

        # MASK
        siocsifnetmask = struct.pack(sockaddr_mt, dev, AF_INET, 0, maskbuf)
        fcntl.ioctl(fd, SIOCSIFNETMASK, siocsifnetmask)

        # ifconfig tun0 up
        ifr2 = struct.pack(flags_mt, dev, 0)
        ifr_ret = fcntl.ioctl(fd, SIOCGIFFLAGS, ifr2)
        cur_flags = struct.unpack(flags_mt, ifr_ret)[1]
        flags = cur_flags | (IFF_UP | IFF_RUNNING)
        ifr_ret = struct.pack(flags_mt, dev, flags)
        ifr_ret = fcntl.ioctl(fd, SIOCSIFFLAGS, ifr_ret)
        return 0
    '''
    def add_route(ip, mask, gw):
        #route add -net $ip mask $mask gw $gw
        try:
            os.system("route add -net %d mask %d gw %d" %(ip, mask, gw))
        except:
            print("add route error")
        else:
            print("add route successfully")

    def enable_tcp_forward():
        with open('/proc/sys/net/ipv4/ip_forward', 'wb+') as ip_forward:
            ip_forward.seek(0)
            ip_forward.write('1')
    '''

    def add_route(dest, mask, gw):
        # sudo strace route add -net 10.10.0.0/16 gw 10.10.0.1
        # ioctl(3, SIOCADDRT, ifr)
        # /usr/include/net/route.h
        pad = '\x00' * 8
        inet_aton = socket.inet_aton
        sockaddr_in_fmt = 'hH4s8s'
        rtentry_fmt = 'L16s16s16sH38s'
        dst = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(dest), pad)
        next_gw = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(gw), pad)
        netmask = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(mask), pad)
        rt_flags = RTF_UP | RTF_GATEWAY
        rtentry = struct.pack(rtentry_fmt,0, dst, next_gw, netmask, rt_flags, '\x00' * 38)
        sock = socket.socket(AF_INET, socket.SOCK_DGRAM, 0)
        fcntl.ioctl(sock.fileno(), SIOCADDRT, rtentry)
        return 0


class encrypt():
    def __init__(self):
        try:
            from Crypto import Random
            from Crypto.Hash import SHA
            from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
            from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
            from Crypto.PublicKey import RSA
        except:
            print("please run \"pip3 install pycrypto\" in shell")

    def build_key():
        # 伪随机数生成器
        random_generator = Random.new().read
        # rsa算法生成实例
        rsa = RSA.generate(1024, random_generator)

        # master的秘钥对的生成
        private_pem = rsa.exportKey()

        with open('master-private.pem', 'w') as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open('master-public.pem', 'w') as f:
            f.write(public_pem)

        # ghost的秘钥对的生成
        private_pem = rsa.exportKey()
        with open('master-private.pem', 'w') as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open('master-public.pem', 'w') as f:
            f.write(public_pem)

    def encrypt(source_data):
        '''对source_data进行加密，密钥ghost-public.pem
          返回密文cipher_data
        '''
        with open('ghost-public.pem') as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            cipher_data = base64.b64encode(cipher.encrypt(source_data))
        return cipher_data

        def decrypt(encrypt_data):
            '''使用私钥ghost-private.pem对encrypt_data解密，
             返回原文data
            '''
        with open('ghost-private.pem') as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            data = cipher.decrypt(base64.b64decode(encrypt_data), random_generator)
        return data

class read_config():
    def __init__(self):
        pass


class transport():
    def set_tunfd(self, tunfd):
        self.tunfd = tunfd

    def get_frame(self, buf):
        if len(buf) <= 20:
            return -1
        pack_len = struct.unpack('!H', buf[2:4])[0]
        if len(buf) < pack_len:
            return -1
        return pack_len

    def recv(self, buf):
        self.buf += buf
        while True:
            #Only one IP package can be written at a time.
            length = self.get_frame(self.buf)
            if length == -1:
                break
            frame = self.buf[:length]
            self.buf = self.buf[length:]
        os.write(self.tunfd, frame)

def connect_to_vpn(addr, port):
    sock = socket.socket()
    addr = (addr, port)
    try:
        sock.connect(addr)
    except socket.error as e:
        print 'Connect to VPN:[%d],[%s]' % (e.errno, e.strerror)
        return None
    sock.setblocking(False)
    return sock

def client_main(ip, netmask, host, port):
    buflen = 65535
    dev, tundev = tunnel.create_tunnel()
    tunfd = tundev.fileno()
    time.sleep(1)
    iret = tunnel.configure(ip, netmask, dev)
    if iret is None:
        print(u'ip config %s error' % dev)
        return sys.exit(1)
    iret = tunnel.add_route('10.10.0.0', '255.255.0.0', '10.10.0.1')
    if iret is None:
        print(u'route config %s error' % dev)
        return sys.exit(1)
    time.sleep(1)

    sock = connect_to_vpn(host, int(port))
    if sock is None:
        print(u'SOCK dev Fail')
        sys.exit(-1)
    client = Transport(sock)
    client.set_tunfd(tunfd)
    sockfd = sock.fileno()
    print(u'SOCK dev OK, FD:[%d]' % sockfd)

    fds = [tunfd, sockfd, ]
    while True:
        rs, _, _ = select.select(fds, [], [])
        for fd in rs:
            if fd == tunfd:
                rcv = os.read(tunfd, buflen)
                if len(rcv) == 0:
                    print(u'TUN recv [0], Continue')
                    continue
                sent_len = sock.send(rcv)
                print('TUN recv, write to SOCK:[%r]' % sent_len)
            elif fd == sockfd:
                rcv = sock.recv(buflen)
                if len(rcv) == 0:
                    print(u'SOCK recv [0], break')
                    os.close(sockfd)
                    break
                print('SOCK recv [%d]' % len(rcv))
                client.recv(rcv)


def server_main(gwip, netmask, lip, lport):
    buflen = 65535
    dev, tundev = tunnel.create_tunnel()
    print('Allocated %s' % dev)
    tunfd = tundev.fileno()
    print(u'TUN dev OK')
    tunnel.configure(dev, gwip, netmask)
    tunnel.enable_tcp_forward()

    sock = socket.socket()
    laddr = (lip, int(lport))
    sock.bind(laddr)
    sock.listen(socket.SOMAXCONN)
    print(u'Sock Listen OK')
    sock.setblocking(False)
    sockfd = sock.fileno()
    clients = {}

    fds = [tunfd, sockfd, ]
    while True:
        try:
            rs, _, _ = select.select(fds, [], [])
        except select.error as e:
            print e
            sys.exit(-1)
        for fd in rs:
            if fd == sockfd:
                cs, ca = sock.accept()
                csfd = cs.fileno()
                fds.append(csfd)
                client = Transport(cs)
                client.set_tunfd(tunfd)
                clients[csfd] = client
                print(u'Remote sock addr: [%s:%d]' % ca)
            elif fd == tunfd:
                print(u'TUN dev recv, rs:[%r]' % rs)
                for client_fd in fds:
                    if client_fd not in [tunfd, sockfd]:
                        os.write(client_fd, os.read(tunfd, buflen))
            else:
                rcv = os.read(fd, buflen)
                if len(rcv) == 0:
                    print(u'SOCK rcv [0]')
                    fds.remove(fd)
                    del clients[fd]
                    continue
                print(u'SOCK recv [%d]' % len(rcv))
                client = clients[fd]
                client.recv(rcv)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', nargs=2)
    parser.add_argument('-l', '--listen', nargs=2)
    parser.add_argument('-c', '--client', nargs=2)
    parser.add_argument('-r', '--remote', nargs=2)
    ns = parser.parse_args(sys.argv[1:])
    if (ns.server and (ns.client or ns.remote) or
            ns.listen and (ns.client or ns.remote) or
            ns.client and (ns.server or ns.listen) or
            ns.remote and (ns.server or ns.listen)):
        print(u'logistic error, client cannot running with server')
        parser.print_usage()
        sys.exit(1)
    if ns.server:
        gwip, netmask = ns.server
        lip, lport = ns.listen
        return server_main(gwip, netmask, lip, lport)
    elif ns.client:
        ip, netmask = ns.client
        host, port = ns.remote
        return client_main(ip, netmask, host, port)


if __name__ == '__main__':
    main()

