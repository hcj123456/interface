#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/11/5 15:22
# software: PyCharm
import json

from common import BaseFuntest, aes
from common.mylogger import log


class Encryption_Interface(object):
    def encryption_interface(self,cases):
        sign = BaseFuntest.get_md5sheng(eval(cases))
        log.info('签名是:{}'.format(sign))
        cases = str(cases).replace('\'', '\"')
        j = json.loads(cases)
        j['sign'] = sign
        log.info('转换为json的数据{}'.format(j))
        data = eval(cases)['data']
        datastr = str(data).replace('\'', '\"')
        dataspace = str(datastr).replace(' ', '')
        log.info('data是：{}'.format(dataspace))
        pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
        e = pc.encrypt(dataspace)  # 加密
        print("加密:", e)
        j['data'] = e
        print('j是{}'.format(j))
        k = str(j).replace('data', 'encrypt_data')
        l = str(k).replace('\'', '\"')
        cases = l
        return cases