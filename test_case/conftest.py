#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/11/11 14:07
# software: PyCharm
import pytest

from common.class_requests import HttpSession
from common.read_data import Read_Yaml_Data
@pytest.fixture
def init():

    cases = Read_Yaml_Data().ret_yaml_data('data','Search_data1')
    yield cases

@pytest.fixture
def init2():
    cases = Read_Yaml_Data().ret_yaml_data('data','Search_data2')
    yield cases

@pytest.fixture
def init1():
    http = HttpSession()
    yield http
# tt = init2()
# print(tt.__next__())

# 1. 调用钩子方法, item 参数这里不用
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport():
    print('------------------------------------')

    # 2. 获取钩子方法的调用结果
    result = yield
    # print('钩子方法的执行结果', result)

    # 3. 从钩子方法的调用结果中获取测试报告
    report = result.get_result()

    # print('从结果中获取测试报告：', report)
    # print('从报告中获取 nodeid：', report.nodeid)
    print('从报告中获取调用步骤：', report.when)
    # print('从报告中获取执行结果：', report.outcome)
    if report.outcome == 'passed':
        print('该步骤执行成功')
    else:
        print("该步骤执行失败")

