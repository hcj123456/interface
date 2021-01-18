#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/9/24 15:25
# software: PyCharm
import os
import time
import unittest
#import HTMLTestRunner
from HTMLTestRunner import HTMLTestRunner

# from test_case.data import TestHttpRequest

suite=unittest.TestSuite()
loader=unittest.TestLoader()
suite.addTest(loader.loadTestsFromTestCase(TestHttpRequest))
filetime = time.strftime("%Y-%m-%d %H_%M_%S", time.localtime())
filename = '{}report.html'.format(filetime)
# 项目目录路径
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
print(BASE_DIR)
# 测试报告所在的目录路径
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
report_file_path = os.path.join(REPORT_DIR, filename)
#第一种方式
with open('test_ report','wb+') as f:
    runner=HTMLTestRunner.HTMLTestRunner(f,2,title='test_report',
                                         description='unittest')
    runner.run(suite)
#第二种方式
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
suite1 = unittest.TestSuite(suite)
test_result = excuteSuiteExportReport('report.html', suite1)
analysisResult(test_result)