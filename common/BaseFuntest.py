#!/usr/bin/env python
#coding=utf-8
import os
import datetime
import hmac
import base64
import random
import time
import string
import requests
import filecmp
#import HTMLTestRunner
import hashlib
import json
from json import *
from hashlib import sha1
import subprocess
import urllib
import unittest
import re
import importlib
import collections
# import dateutil.parser
import HTMLTestRunner

from common.mylogger import log
import sys
from collections import OrderedDict
#import imp
#import imp
import importlib

importlib.reload(sys)



def excuteSuiteExportReport(reportFileName, suite):
    fr = open(reportFileName, 'wb')
    report = HTMLTestRunner.HTMLTestRunner(stream=fr, verbosity=2, title='测试报告', description='测试报告详情')
    test_result = report.run(suite)
    return test_result

def analysisResult(test_result):
    failure_count = test_result.failure_count
    error_count = test_result.error_count
    print("用例执行失败个数为%s" % failure_count)
    print("用例执行错误个数为%s" % error_count)
    if failure_count == 0 and error_count == 0:
        print ("正常退出")
    else:
        print ("异常退出")
        raise Exception("用例执行失败")


def get_md5(dateSign):
    # data字段的值进行排序
    l_list = []
    l = dateSign['data']
    # data按照顺序读取
    for d in sorted(l):
        m = '{0}{1}{2}{3}{4}{5}{6}{7}'.format('\"', d, '\"', ':', '\"', l[d], '\"', ',')
        l_list.append(m)
        l_list_string = "".join(l_list)
    s_list = []  # 新建空列表，存储date的值
    # 循环读取date中的值
    for i in sorted(dateSign):
        if i == 'data':
            n = '{0}{1}'.format(i, '=')
            s_list.append(n)
            zifu01 = '{'
            s_list.append(zifu01)
            s_list.append(l_list_string)
            zifu02 = '}'
            s_list.append(zifu02)
            zifu = "&"
            s_list.append(zifu)
        else:
            s = '{0}{1}{2}{3}'.format(i, '=', dateSign[i], '&')
            s_list.append(s)
    # 列表转换为str
    s_list_string = "".join(s_list)
    signRegion_key = s_list_string + "key=2256B431D45F53B02BFF05C3942E60D7"
    # 单引号转换为双引号
    signRegion_test = signRegion_key.replace('\'', '\"')
    # 空格替换
    signRegion_test01 = signRegion_test.replace(': ', ':')
    signRegion_test02 = signRegion_test01.replace(',}', '}')
    signRegion = signRegion_test02.replace(', ', ',')
    log.info('加密的值为：{0}'.format(signRegion))
    print('加密的值为：{0}'.format(signRegion))
    m = hashlib.md5()  # 创建md5对象
    m.update(signRegion.encode("utf8"))
    sign = m.hexdigest()
    up_sign = sign.upper()
    print('加密后的sign:{0}'.format(up_sign))
    return up_sign

def get_md5sheng(dateSign):
    # data字段的值进行排序
    l_list = []
    l = dateSign['data']
    # data按照顺序读取
    for d in sorted(l):
        m = '{0}{1}{2}{3}{4}{5}{6}{7}'.format('\"', d, '\"', ':', '\"', l[d], '\"', ',')
        l_list.append(m)
        l_list_string = "".join(l_list)
    s_list = []  # 新建空列表，存储date的值
    # 循环读取date中的值
    for i in sorted(dateSign):
        if i == 'data':
            n = '{0}{1}'.format(i, '=')
            s_list.append(n)
            zifu01 = '{'
            s_list.append(zifu01)
            s_list.append(l_list_string)
            zifu02 = '}'
            s_list.append(zifu02)
            zifu = "&"
            s_list.append(zifu)
        else:
            s = '{0}{1}{2}{3}'.format(i, '=', dateSign[i], '&')
            s_list.append(s)
    # 列表转换为str
    s_list_string = "".join(s_list)
    signRegion_key = s_list_string + "key=C9C9F54F74BD35DE5242885762E99E8B"
    # 单引号转换为双引号
    signRegion_test = signRegion_key.replace('\'', '\"')
    # 空格替换
    signRegion_test01 = signRegion_test.replace(': ', ':')
    signRegion_test02 = signRegion_test01.replace(',}', '}')
    signRegion = signRegion_test02.replace(', ', ',')
    signRegionnew = signRegion.replace('\"biz_param\":\"','\"biz_param\":')
    signRegionnew01 = signRegionnew.replace('13709301823\"}\"','13709301823\"}')
    log.info('加密的值为：{0}'.format(signRegionnew01))
    print('加密的值为：{0}'.format(signRegionnew01))
    m = hashlib.md5()  # 创建md5对象
    m.update(signRegionnew01.encode("utf8"))
    sign = m.hexdigest()
    up_sign = sign.upper()
    print('加密后的sign:{0}'.format(up_sign))
    return up_sign

def get_md5xiamen(dateSign):
    # data字段的值进行排序
    l_list = []
    l = dateSign['data']
    # data按照顺序读取
    for d in sorted(l):
        m = '{0}{1}{2}{3}{4}{5}{6}{7}'.format('\"', d, '\"', ':', '\"', l[d], '\"', ',')
        l_list.append(m)
        l_list_string = "".join(l_list)
    s_list = []  # 新建空列表，存储date的值
    # 循环读取date中的值
    for i in sorted(dateSign):
        if i == 'data':
            n = '{0}{1}'.format(i, '=')
            s_list.append(n)
            zifu01 = '{'
            s_list.append(zifu01)
            s_list.append(l_list_string)
            zifu02 = '}'
            s_list.append(zifu02)
            zifu = "&"
            s_list.append(zifu)
        else:
            s = '{0}{1}{2}{3}'.format(i, '=', dateSign[i], '&')
            s_list.append(s)
    # 列表转换为str
    s_list_string = "".join(s_list)
    signRegion_key = s_list_string + "key=2156B331D45F53B02BFF05C3942E60D1"
    # 单引号转换为双引号
    signRegion_test = signRegion_key.replace('\'', '\"')
    # 空格替换
    signRegion_test01 = signRegion_test.replace(': ', ':')
    signRegion_test02 = signRegion_test01.replace(',}', '}')

    signRegion = signRegion_test02.replace(', ', ',')
    signRegionnew = signRegion.replace('\"biz_param\":\"','\"biz_param\":')
    signRegionnew01 = signRegionnew.replace('13709301823\"}\"','13709301823\"}')
    log.info('加密的值为：{0}'.format(signRegionnew01))
    print('加密的值为：{0}'.format(signRegionnew01))
    m = hashlib.md5()  # 创建md5对象
    m.update(signRegionnew01.encode("utf8"))
    sign = m.hexdigest()
    up_sign = sign.upper()
    print('加密后的sign:{0}'.format(up_sign))
    return up_sign

def get_md5fuzhou(dateSign):
    # data字段的值进行排序
    l_list = []
    l = dateSign['data']
    # data按照顺序读取
    for d in sorted(l):
        m = '{0}{1}{2}{3}{4}{5}{6}{7}'.format('\"', d, '\"', ':', '\"', l[d], '\"', ',')
        l_list.append(m)
        l_list_string = "".join(l_list)
    s_list = []  # 新建空列表，存储date的值
    # 循环读取date中的值
    for i in sorted(dateSign):
        if i == 'data':
            n = '{0}{1}'.format(i, '=')
            s_list.append(n)
            zifu01 = '{'
            s_list.append(zifu01)
            s_list.append(l_list_string)
            zifu02 = '}'
            s_list.append(zifu02)
            zifu = "&"
            s_list.append(zifu)
        else:
            s = '{0}{1}{2}{3}'.format(i, '=', dateSign[i], '&')
            s_list.append(s)
    # 列表转换为str
    s_list_string = "".join(s_list)
    signRegion_key = s_list_string + "key=4e10b34b049b99d419fd"
    # 单引号转换为双引号
    signRegion_test = signRegion_key.replace('\'', '\"')
    # 空格替换
    signRegion_test01 = signRegion_test.replace(': ', ':')
    signRegion_test02 = signRegion_test01.replace(',}', '}')
    signRegion = signRegion_test02.replace(', ', ',')
    signRegionnew = signRegion.replace('\"biz_param\":\"','\"biz_param\":')
    signRegionnew01 = signRegionnew.replace('13709301823\"}\"','13709301823\"}')
    log.info('加密的值为：{0}'.format(signRegionnew01))
    print('加密的值为：{0}'.format(signRegionnew01))
    m = hashlib.md5()  # 创建md5对象
    m.update(signRegionnew01.encode("utf8"))
    sign = m.hexdigest()
    up_sign = sign.upper()
    print('加密后的sign:{0}'.format(up_sign))
    return up_sign


def get_md5_dataNull(dateSign):
    # data字段的值进行排序
    s_list = []  # 新建空列表，存储date的值
    # 循环读取date中的值
    for i in sorted(dateSign):
        s = '{0}{1}{2}{3}'.format(i, '=', dateSign[i], '&')
        s_list.append(s)
    print(s_list)

    # 列表转换为str
    s_list_string = "".join(s_list)
    signRegion_key = s_list_string + "key=2156B331D45F53B02BFF05C3942E60D7"
    # 单引号转换为双引号
    signRegion_test = signRegion_key.replace('\'', '\"')
    # 空格替换
    signRegion_test01 = signRegion_test.replace(': ', ':')
    signRegion = signRegion_test01.replace(', ', ',')
    print('加密的值为：{0}'.format(signRegion))
    m = hashlib.md5()  # 创建md5对象
    m.update(signRegion.encode("utf8"))
    sign = m.hexdigest()
    up_sign = sign.upper()
    print('加密后的sign:{0}'.format(up_sign))
    return up_sign

def getAccessToken(url, date, headers):
    print ('##########获取access_token############')
    r = requests.post(url=url, json=date, headers=headers)
    print (r.text)
    datas = json.loads(r.text.encode('utf-8')).get('data')
    print('datas{0}:'.format(datas))
    access_token = datas['access_token']
    print ('access_token: {0}'.format(access_token))
    return access_token

def getFlags(url, date, headers,**kwargs):
    print('请求URL为：%s' % url)
    print('请求参数为：%s' % date)
    r = requests.post(url=url, json=date, headers=headers)
    print('响应头为：{0}'.format(r.headers))
    print('返回的结果为：{0}'.format(r.text))
    print('请求响应时间为：%s' % r.elapsed.total_seconds())
    # python2.6没有total_seconds（）方法。
    # datas = json.loads(r.text.encode('utf-8')).get('data')
    # print('datas{0}:'.format(datas))
    flags = json.loads(r.text.encode('utf-8')).get('flag')
    print('flags:{0}'.format(flags))
    print(r.status_code, r.reason)
    return flags

def getFlags_base64(url, date, headers,stream=True,**kwargs):
    print('请求URL为：%s' % url)
    print('请求参数为：%s' % date)
    r = requests.post(url=url, json=date, headers=headers, stream=True)
    print('响应头为：{0}'.format(r.headers))
    # print('返回的结果为：{0}'.format(r.text))
    print('请求响应时间为：%s' % r.elapsed.total_seconds())
    # python2.6没有total_seconds（）方法。
    # datas = json.loads(r.text.encode('utf-8')).get('data')
    # print('datas{0}:'.format(datas))
    flags = json.loads(r.text).get('flag')
    print('flags:{0}'.format(flags))
    print(r.status_code, r.reason)
    return flags

def getTotal(url, date, headers, **kwargs):
    # print('请求URL为：%s' % url)
    # print('请求参数为：%s' % date)
    r = requests.post(url=url, json=date, headers=headers)
    # print('响应头为：{0}'.format(r.headers))
    # print('返回的结果为：{0}'.format(r.text))
    # datas = json.loads(r.text.encode('utf-8')).get('data')
    # print('datas{0}:'.format(datas))

    data = json.loads(r.text.encode('utf-8')).get('data')
    # print('data:{0}'.format(data))
    total = data['total']
    print('total:',total)
    return total

def getData(url, date, headers,**kwargs):
    # print('请求URL为：%s' % url)
    # print('请求参数为：%s' % date)
    r = requests.post(url=url, json=date, headers=headers)
    # print('响应头为：{0}'.format(r.headers))
    # print('返回的结果为：{0}'.format(r.text))
    # datas = json.loads(r.text.encode('utf-8')).get('data')
    # print('datas{0}:'.format(datas))
    data = json.loads(r.text.encode('utf-8')).get('data')
    # print('data:{0}'.format(data))
    return data


#start 获取文件名
def get_fileName(filename):
    (filepath,tempfilename) = os.path.split(filename);
    (shotname,extension) = os.path.splitext(tempfilename);
    return shotname


