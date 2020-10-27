#!/usr/bin/env python
#coding=utf-8
"""
=============================
author:'Dayle'
time:2019/9/1
E-mail:liudl7@lenovo.com
=============================
"""
import os
import time

# from HTMLTestRunnerNew import HTMLTestRunner


from common.conifg import myconf
from common.constant import CASES_DIR
from common.constant import REPORT_DIR
from common.mylogger import log
import unittest
from common.BaseFuntest import excuteSuiteExportReport, analysisResult
import os
import shutil

"""
项目启动文件
"""
log.info('----------------------------------正在开启测试运行程序-------------------------------------------------')
# 第一步：创建测试套件
suite = unittest.TestSuite()

# 第二步：将用例添加到套件
loader = unittest.TestLoader()
suite.addTest(loader.discover(CASES_DIR))

# 第三步：执行用例，生成测试报告

# 读取配置文件中的report文件名
# report_name = myconf.get('report', file_name)

# 获取当前时间，拼接文件名称
filetime = time.strftime("%Y-%m-%d %H_%M_%S", time.localtime())
# filename = '{}report.html'.format(filetime)
filename='report.html'
# report_file_path = os.path.join(REPORT_DIR, filename)

# with open(report_file_path, 'wb') as fb:
    # runner = HTMLTestRunner(stream=fb,
    #                         verbosity=2,
    #                         title='21期接口项目',
    #                         description='21期的项目实战',
    #                         tester='Dayle')
"""
with open(filename, 'wb') as fb:
    runner = HTMLTestRunner.HTMLTestRunner(stream=fb,
                title='My unit test',
                description='This demonstrates the report output by HTMLTestRunner.')
    runner.run(suite)
"""
suite1 = unittest.TestSuite(suite)
test_result = excuteSuiteExportReport('report.html', suite1)
#windows系统使用copy命令 liunx系统使用cp命令
# os.system(r'copy E:\autoscript\testapi_fujianpublic\data\cases.xlsx E:\autoscript\testapi_fujianpublic\common')
# os.system(r'cp /root/apiAutomationTestNew/testapi_fujianpublic/data/cases.xlsx /var/lib/jenkins/workspace/testapidemo_fujianpublic')
# os.system(r'cp /root/apiAutomationTestNew/testapi_fujianpublic/logs/log.log /var/lib/jenkins/workspace/testapidemo_fujianpublic')
# os.system(r'sudo rm -rf /root/apiAutomationTestNew/testapi_fujianpublic/logs/log.log')

analysisResult(test_result)


log.info('----------------------------------本次所有的用例执行完毕-------------------------------------------------')
