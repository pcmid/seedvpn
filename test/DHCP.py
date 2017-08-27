''' 分配ip给用户 '''
from IPy import IP

def __init__(self, ip):
    self.IPPool = IP(ip)
    # 去掉网关，服务器和广播地址
    self.usedIPList = [self.IPPool[0], self.IPPool[1], self.IPPool[-1]]


def addUsedIP(self, usdIP):
    self.usedIPList.append(usdIP)


def removeUsedIP(self, unUsedIP):
    self.usedIPList.remove(IP(unUsedIP))


def assignIP(self):
    resIP = [ip for ip in self.IPPool if ip not in self.usedIPList][0]
    self.addUsedIP(resIP)
    return resIP.strNormal()
