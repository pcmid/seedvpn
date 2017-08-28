#!/usr/bin/env python3
# coding=utf-8

from Crypto.Cipher import AES
from Crypto import Random
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S %a, %d %b %Y')

'''
class prpcrypt():
    def __init__(self, key):
        count = len(key)
        add = (16 - count)
        self.key = key + ('\0' * add)
        self.mode = AES.MODE_CBC
        #self.iv = Random.new().read(AES.block_size)

        self.iv = b'1' * 16

    def encrypt(self, text):
        cipher = AES.new(self.key, self.mode, self.iv)
        self.ciphertext =  cipher.encrypt(text)
        return self.ciphertext

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(text)
        print(len(self.iv))
        return plain_text[:len(self.iv)]
'''


class AES_Encrypt(object):
    def __init__(self, key):
        count = len(key)
        if count < 16:
            add = (16 - count)
            #\0 backspace
            self.key = key + ('\0' * add)
        elif count > 16 and count < 32:
            add = (32 - count)
            self.key = key + ('\0' * add)
        else:
            logging.error("密码太长")
        self.mode = AES.MODE_CBC
        #self.iv = Random.new().read(AES.block_size)
        self.iv = b'1' * 16

    def encrypt(self, text):
        cipher = AES.new(self.key, self.mode, self.iv)
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 为了兼顾效率和安全性，采用AES-128
        length = 16
        count = len(text)
        if count < length:
            add = length - count
            # add always less than 16
            text = text + b'\0' * add
        elif count > length:
            add = (length - (count % length))
            text = text + b'\0' * add
        logging.debug("加密前数据：%s" % (text))
        self.cipher_text = cipher.encrypt(text) + self.iv
        logging.debug("加密后的数据: %s" % (self.cipher_text))
        return self.cipher_text

    def decrypt(self, text):
        cipher = AES.new(self.key, self.mode, self.iv)
        if len(text) % 16 == 0:
            plain_text = cipher.decrypt(text)
            logging.debug("解密后的数据: %s" % (plain_text))
            return plain_text
        else:
            logging.debug("解密无效")
            return "-1"


if __name__ == "__main__":
    pc = AES_Encrypt("qwert")  # 初始化密钥
    pc2 = AES_Encrypt("qwert")
    e = pc.encrypt(b"LOGIN:qwert")  # 加密
    d = pc2.decrypt(e)  # 解密
    print("加密:", e)
    print("解密:", d)
