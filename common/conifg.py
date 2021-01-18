#!/usr/bin/env python
#-*- coding:UTF-8 -*-
"""
=============================
author:'liudl'
time:2019/8/27
E-mail:liudl7@lenovo.com
=============================
"""
import os
from common.configparser import ConfigParser   # 用于生成和修改常见配置文档
from common.constant import CONF_DIR


class MyConfig(ConfigParser):
    """读取配置文件的类"""
    def __init__(self):
        super().__init__()

        c = ConfigParser()
        c.read(os.path.join(CONF_DIR, 'env.ini'), encoding='utf8')
        env = c.getint('env', 'switch')
        # 根据开关的值，分别读取不同环境的配置文件
        if env == 1:
            self.read(os.path.join(CONF_DIR, 'conf.ini'), encoding='utf8')
        elif env == 2:
            self.read(os.path.join(CONF_DIR, 'conf1.ini'), encoding='utf8')
        else:
            self.read(os.path.join(CONF_DIR, 'conf.ini'), encoding='utf8')


myconf = MyConfig()





# def myconfig():
#     conf = ConfigParser()
#     conf.read(r"E:\python\py21_apt_test\conf\conf.ini")
#     return conf
#
#
# my_conf = myconfig()
