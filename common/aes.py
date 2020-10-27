#!/usr/bin/env python
#coding=utf-8
from Crypto.Cipher import AES
import base64
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Cipher import AES
from binascii import b2a_hex, b2a_base64, a2b_hex, a2b_base64


class PrpCrypt(object):

    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0102030405060708')
        text = text.encode('utf-8')

        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        text = self.pkcs7_padding(text)
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        # return b2a_hex(self.ciphertext)
        encrypt_data = str(base64.b64encode(self.ciphertext))
        encrypt_data_delete_b = encrypt_data.replace("b'","")
        encrypt_data_delete_bfen = encrypt_data_delete_b.replace("'","")
        return encrypt_data_delete_bfen


    @staticmethod
    def pkcs7_padding(data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        # 偏移量'0102030405060708'
        cryptor = AES.new(self.key, self.mode, b'0102030405060708')
        plain_text = cryptor.decrypt(a2b_base64(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip('\0')
        # return bytes.decode(plain_text)

    def encryption(password):
        pc = PrpCrypt('abc')  # 初始化密钥
        e = pc.encrypt("abcdefg").decode()  # 加密
        print(base64.b64encode(bytes().fromhex(e)))


# 加解密
if __name__ == '__main__':
    pc = PrpCrypt('417cce41608b7801')  # 初始化密钥
    data = '{"app_type":"0","appid":"4f5b8a312de57b82"}{"app_type":"0","appid":"4f5b8a312de57b82"}{"app_type":"0","appid":"4f5b8a312de57b82"}'
    print(type(data))
    e = pc.encrypt(data)  # 加密
    print("加密:", e)
    d = pc.decrypt(e)  # 解密
    print("解密:",d)


