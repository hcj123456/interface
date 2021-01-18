#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/10/23 16:07
# software: PyCharm
import decimal
import os
import unittest

import pytest

from common.conifg import myconf
from common.class_requests import HttpSession
from common.constant import DATA_DIR
from common.do_mysql import ReadSQL
from common.mylogger import log
from common.read_excel import ReadExcel
from common.read_data import Read_Yaml_Data
from common.test_replace import data_replace
from ddt import ddt, data
from common.test_replace import ConText
from common import BaseFuntest
from common import aes
import json
# import ddt
from common.Encryption_interface import Encryption_Interface
from common.Access_token import Access_Token

# data_file_path = os.path.join(DATA_DIR, 'data.yml')


#@ddt
#(unittest.TestCase)
class Test_ShengZhiTestCase_001:
    """省直公共服务接口"""

    # excel = ReadExcel(data_file_path, 'hcj')
    # cases = excel.read_data_obj()
    # cases = Read_Yaml_Data().ret_yaml_data('data','Search_data1')
    # print(cases)
    # print('cases', cases)

    #http = HttpSession()
    # db = ReadSQL()
    #@data(*cases)
    def test_shengzhi_public(self,init,init1):
        #print(case)
        # 第一步：准备用例数据
        # url = myconf.get('url', 'url') + case.url  # 读取配置文件和Excel中的url地址进行拼接
        # url = myconf.get('url', 'url')
        #url = case.url
        url = init[3][1]
        # 替换用例参数
        #case.json = data_replace(str(case.json))
        json = data_replace(str(init[4][1]))


        # if case.interface == '加密接口':
        #     case.json = Encryption_Interface().encryption_interface(case,case.json)

            # sign = BaseFuntest.get_md5sheng(eval(case.json))
            # log.info('签名是:{}'.format(sign))
            # case.json = str(case.json).replace('\'', '\"')
            # j = json.loads(case.json)
            # j['sign'] = sign
            # log.info('转换为json的数据{}'.format(j))
            # data = eval(case.json)['data']
            # datastr = str(data).replace('\'', '\"')
            # dataspace = str(datastr).replace(' ', '')
            # log.info('data是：{}'.format(dataspace))
            # pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
            # e = pc.encrypt(dataspace)  # 加密
            # print("加密:", e)
            # j['data']=e
            # print('j是{}'.format(j))
            # k = str(j).replace('data','encrypt_data')
            # l = str(k).replace('\'', '\"')
            # case.json = l


        # if case.interface == '获取token':
        json,pc = Access_Token().access_token(json,url)
        # sign = BaseFuntest.get_md5sheng(eval(case.json))
        # log.info('签名是:{}'.format(sign))
        # case.json = str(case.json).replace('\'', '\"')
        # j = json.loads(case.json)
        # j['sign'] = sign
        # log.info('转换为json的数据{}'.format(j))
        # data = eval(case.json)['data']
        # datastr = str(data).replace('\'', '\"')
        # dataspace = str(datastr).replace(' ', '')
        # log.info('data是：{}'.format(dataspace))
        # pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
        # e = pc.encrypt(dataspace)  # 加密
        # print("加密:", e)
        # j['data']=e
        # print('j是{}'.format(j))
        # k = str(j).replace('data','encrypt_data')
        # l = str(k).replace('\'', '\"')
        # case.json = l
        # log.info('请求的参数是：{}'.format(case.json))
        # # 第二步 发送请求，获取结果
        # log.info('正在请求地址{}'.format(url))
        response = init1.request(method=init[2][1], url=url, json=eval(json))
        res = response.json()
        log.info('返回的结果是:{}'.format(res))
        datas_encrypt = res['encrypt_data']
        log.info("datas_encrypt是：{}".format(datas_encrypt))
        d = pc.decrypt(datas_encrypt)  # 解密
        bianma_d = d.encode().split(b'\x08\x08\x08\x08\x08\x08\x08\x08')
        bianma_d_str = str(bianma_d)
        bianma_d_str_de = bianma_d_str.replace("[b'","")
        bianma_d_str_de_de = bianma_d_str_de.replace("', b'']","")
        bianma_d_str_de_de_de = eval(bianma_d_str_de_de)
        access_token = bianma_d_str_de_de_de['access_token']
        log.info("access_token:{}".format(access_token))
        # 将提取接口返回数据，保存为临时变量
        setattr(ConText, 'access_token', access_token)

        # json = eval(case.json)
        # log.info('请求的参数是：{}'.format(str(case.json)))
        # # 第二步 发送请求，获取结果
        # log.info('正在请求地址{}'.format(url))
        # response = self.http.request(method=case.method, url=url, json=eval(case.json))
        # res = response.json()
        # log.info('返回的结果是:{}'.format(res))
        res_code = res['flag']  # 根据接口文档获取出来的是str格式


        # 第三步 比对预期结果和实际结果
        try:
            # self.assertEqual(str(init[5][1]), res_code)
            assert str(init[5][1]) == res_code,"实际结果与预期不符合"
        except AssertionError as e:
            # 用例执行未通过
            # self.assertNotEqual(str(case.excepted), res_code)
            # self.excel.write_data(row=case.case_id + 1, column=8, value='未通过')
            log.info('{}:用例执行未通过'.format(init[0][1]))
            log.info('请求的地址：{}'.format(url))
            log.info('请求的参数是：{}'.format(json))
            log.info('返回的结果是:{}'.format(res))  # 执行不通过返回对应结果到日志
            log.exception(e)
            raise e
        else:
        #     self.excel.write_data(row=case.case_id + 1, column=8, value='通过')
            log.info('{}:用例执行通过'.format(init[0][1]))



# @ddt
# @pytest.mark.skip(reason='Test_ShengZhiTestCase_002这个case不执行')
class Test_ShengZhiTestCase_002:
    """省直公共服务接口"""

    # excel = ReadExcel(data_file_path, 'hcj')
    # cases = excel.read_data_obj()
    #cases = Read_Yaml_Data().ret_yaml_data('data','Search_data2')
    # print(cases)
    # print('cases', cases)

    #http = HttpSession()
    # db = ReadSQL()
    #@data(*cases)
    def test_shengzhi_public(self,init2,init1):
        #print(case)
        # 第一步：准备用例数据
        # url = myconf.get('url', 'url') + case.url  # 读取配置文件和Excel中的url地址进行拼接
        # url = myconf.get('url', 'url')
        url = init2[3][1]
        # 替换用例参数
        json = data_replace(str(init2[4][1]))


        # if case.interface == '加密接口':
        json = Encryption_Interface().encryption_interface(json)
        # sign = BaseFuntest.get_md5sheng(eval(case.json))
        # log.info('签名是:{}'.format(sign))
        # case.json = str(case.json).replace('\'', '\"')
        # j = json.loads(case.json)
        # j['sign'] = sign
        # log.info('转换为json的数据{}'.format(j))
        # data = eval(case.json)['data']
        # datastr = str(data).replace('\'', '\"')
        # dataspace = str(datastr).replace(' ', '')
        # log.info('data是：{}'.format(dataspace))
        # pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
        # e = pc.encrypt(dataspace)  # 加密
        # print("加密:", e)
        # j['data']=e
        # print('j是{}'.format(j))
        # k = str(j).replace('data','encrypt_data')
        # l = str(k).replace('\'', '\"')
        # case.json = l


        # if case.interface == '获取token':
        #     sign = BaseFuntest.get_md5sheng(eval(case.json))
        #     log.info('签名是:{}'.format(sign))
        #     case.json = str(case.json).replace('\'', '\"')
        #     j = json.loads(case.json)
        #     j['sign'] = sign
        #     log.info('转换为json的数据{}'.format(j))
        #     data = eval(case.json)['data']
        #     datastr = str(data).replace('\'', '\"')
        #     dataspace = str(datastr).replace(' ', '')
        #     log.info('data是：{}'.format(dataspace))
        #     pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
        #     e = pc.encrypt(dataspace)  # 加密
        #     print("加密:", e)
        #     j['data']=e
        #     print('j是{}'.format(j))
        #     k = str(j).replace('data','encrypt_data')
        #     l = str(k).replace('\'', '\"')
        #     case.json = l
        #     log.info('请求的参数是：{}'.format(case.json))
        #     # 第二步 发送请求，获取结果
        #     log.info('正在请求地址{}'.format(url))
        #     response = self.http.request(method=case.method, url=url, json=eval(case.json))
        #     res = response.json()
        #     log.info('返回的结果是:{}'.format(res))
        #     datas_encrypt = res['encrypt_data']
        #     log.info("datas_encrypt是：{}".format(datas_encrypt))
        #     d = pc.decrypt(datas_encrypt)  # 解密
        #     bianma_d = d.encode().split(b'\x08\x08\x08\x08\x08\x08\x08\x08')
        #     bianma_d_str = str(bianma_d)
        #     bianma_d_str_de = bianma_d_str.replace("[b'","")
        #     bianma_d_str_de_de = bianma_d_str_de.replace("', b'']","")
        #     bianma_d_str_de_de_de = eval(bianma_d_str_de_de)
        #     access_token = bianma_d_str_de_de_de['access_token']
        #     log.info("access_token:{}".format(access_token))
        #     # 将提取接口返回数据，保存为临时变量
        #     setattr(ConText, 'access_token', access_token)

        # json = eval(case.json)
        log.info('请求的参数是：{}'.format(str(json)))
        # 第二步 发送请求，获取结果
        log.info('正在请求地址{}'.format(url))
        response = init1.request(method=init2[2][1], url=url, json=eval(json))
        res = response.json()
        log.info('返回的结果是:{}'.format(res))
        res_code = res['flag']  # 根据接口文档获取出来的是str格式


        # 第三步 比对预期结果和实际结果
        try:
            # self.assertEqual(str(case.excepted), res_code)
            assert str(init2[5][1]) == res_code,"实际结果与预期结果不符合"

        except AssertionError as e:
            # 用例执行未通过
            # self.assertNotEqual(str(case.excepted), res_code)
            # self.excel.write_data(row=case.case_id + 1, column=8, value='未通过')
            log.info('{}:用例执行未通过'.format(init2[0][1]))
            log.info('请求的地址：{}'.format(url))
            log.info('请求的参数是：{}'.format(json))
            log.info('返回的结果是:{}'.format(res))  # 执行不通过返回对应结果到日志
            log.exception(e)
            raise e
        else:
        #     self.excel.write_data(row=case.case_id + 1, column=8, value='通过')
            log.info('{}:用例执行通过'.format(init2[0][1]))