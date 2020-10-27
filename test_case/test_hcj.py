#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/10/23 16:07
# software: PyCharm
import decimal
import os
import unittest
from common.conifg import myconf
from common.class_requests import HttpSession
from common.constant import DATA_DIR
from common.do_mysql import ReadSQL
from common.mylogger import log
from common.read_excel import ReadExcel
from common.test_replace import data_replace
from ddt import ddt, data
from common.test_replace import ConText
from common import BaseFuntest
from common import aes
import json
# import ddt


data_file_path = os.path.join(DATA_DIR, 'cases1.xlsx')


@ddt
class Test_ShengZhiTestCase(unittest.TestCase):
    """省直公共服务接口"""
    excel = ReadExcel(data_file_path, 'hcj')
    cases = excel.read_data_obj()
    # print('cases', cases)
    http = HttpSession()
    # db = ReadSQL()

    @data(*cases)
    def test_shengzhi_public(self, case):
        # 第一步：准备用例数据
        # url = myconf.get('url', 'url') + case.url  # 读取配置文件和Excel中的url地址进行拼接
        # url = myconf.get('url', 'url')
        url = case.url
        # 替换用例参数
        case.json = data_replace(case.json)


        if case.interface == '加密接口':
            sign = BaseFuntest.get_md5sheng(eval(case.json))
            log.info('签名是:{}'.format(sign))
            j = json.loads(case.json)
            j['sign'] = sign
            log.info('转换为json的数据{}'.format(j))
            data = eval(case.json)['data']
            datastr = str(data).replace('\'', '\"')
            dataspace = str(datastr).replace(' ', '')
            log.info('data是：{}'.format(dataspace))
            pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
            e = pc.encrypt(dataspace)  # 加密
            print("加密:", e)
            j['data']=e
            print('j是{}'.format(j))
            k = str(j).replace('data','encrypt_data')
            l = str(k).replace('\'', '\"')
            case.json = l


        if case.interface == '获取token':
            sign = BaseFuntest.get_md5sheng(eval(case.json))
            log.info('签名是:{}'.format(sign))
            j = json.loads(case.json)
            j['sign'] = sign
            log.info('转换为json的数据{}'.format(j))
            data = eval(case.json)['data']
            datastr = str(data).replace('\'', '\"')
            dataspace = str(datastr).replace(' ', '')
            log.info('data是：{}'.format(dataspace))
            pc = aes.PrpCrypt('C9C9F54F74BD35DE5242885762E99E8E')  # 初始化密钥
            e = pc.encrypt(dataspace)  # 加密
            print("加密:", e)
            j['data']=e
            print('j是{}'.format(j))
            k = str(j).replace('data','encrypt_data')
            l = str(k).replace('\'', '\"')
            case.json = l
            log.info('请求的参数是：{}'.format(case.json))
            # 第二步 发送请求，获取结果
            log.info('正在请求地址{}'.format(url))
            response = self.http.request(method=case.method, url=url, json=eval(case.json))
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
        log.info('请求的参数是：{}'.format(case.json))
        # 第二步 发送请求，获取结果
        log.info('正在请求地址{}'.format(url))
        response = self.http.request(method=case.method, url=url, json=eval(case.json))
        res = response.json()
        log.info('返回的结果是:{}'.format(res))
        res_code = res['flag']  # 根据接口文档获取出来的是str格式


        # 第三步 比对预期结果和实际结果
        try:
            self.assertEqual(str(case.excepted), res_code)

        except AssertionError as e:
            # 用例执行未通过
            # self.assertNotEqual(str(case.excepted), res_code)
            self.excel.write_data(row=case.case_id + 1, column=8, value='未通过')
            log.info('{}:用例执行未通过'.format(case.title))
            log.info('请求的地址：{}'.format(url))
            log.info('请求的参数是：{}'.format(case.json))
            log.info('返回的结果是:{}'.format(res))  # 执行不通过返回对应结果到日志
            log.exception(e)
            raise e
        else:
            self.excel.write_data(row=case.case_id + 1, column=8, value='通过')
            log.info('{}:用例执行通过'.format(case.title))