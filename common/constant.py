#!/usr/bin/env python
#-*- coding:UTF-8 -*-
"""
=============================
author:'Dayle'
time:2019/9/1
E-mail:liudl7@lenovo.com
=============================
"""
import os

"""
常量模块，
获取项目目录的路径，保存

项目路径：
用例类所在的目录：
配置文件的路径：
用例数据的路径：
日志文件的路径：
测试报告的路径：
"""
# E:\class21_api_project

print(__file__)

# 项目目录路径
# res = os.path.dirname(__file__)
# print(os.path.dirname(res))
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
print(BASE_DIR)
# 测试用例所在的目录路径
CASES_DIR = os.path.join(BASE_DIR, 'test_case')

# 测试报告所在的目录路径
REPORT_DIR = os.path.join(BASE_DIR, 'reports')

# 日志文件所在的目录路径
LOG_DIR = os.path.join(BASE_DIR, 'log')

# 配置文件所在的目录路径
CONF_DIR = os.path.join(BASE_DIR, 'conf')

# 用例数据所在的目录路径
DATA_DIR = os.path.join(BASE_DIR, 'test_data')

#读取yaml中的数据
# YAML_DIR= os.path.join(BASE_DIR, 'test_data')
