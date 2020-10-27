#!/usr/bin/env python
#-*- coding:UTF-8 -*-
"""
=============================
author:'liudl'
time:2019/8/27
E-mail:liudl7@lenovo.com
=============================
"""
import logging
from logging.handlers import RotatingFileHandler,TimedRotatingFileHandler
import os
from common.conifg import myconf
from common.constant import LOG_DIR


# 读取配置文件中日志相关的配置
# 读取日志收集器等级
log_level = myconf.get('log', 'log_level')
# 读取输出到控制台的等级
sh_level = myconf.get('log', 's_level')
# 读取输出到文件的等级
fh_level = myconf.get('log', 'f_level')
# 读取日志保存的文件名
name = myconf.get('log', 'filename')

# 拼接日志文件路径
file_path = os.path.join(LOG_DIR, name)


class MyLogging(object):

    def __new__(cls, *args, **kwargs):
        """创建对象"""
        my_log = logging.getLogger('my_log')
        # 第一步 创建一个日志收集器
        my_log.setLevel(log_level)

        # 第二步：创建日志输出渠道
        sh = logging.StreamHandler()
        sh.setLevel(sh_level)

        # fh = logging.FileHandler(file_path, encoding='utf8')
        # 创建一个按文件大小进行轮转的输出渠道（文件）
        # fh = RotatingFileHandler(filename='my.log', mode='a', encoding='utf8', maxBytes=1024*1024, backupCount=3)
        # 按时间间隔轮转进行轮转的输出渠道（文件）
        fh = TimedRotatingFileHandler(filename=file_path, encoding='utf8', when='D', interval=1, backupCount=7)
        fh.setLevel(fh_level)

        # 第三步：将日志收集器和输出渠道进行绑定
        my_log.addHandler(sh)
        my_log.addHandler(fh)

        # 指定日志输出的格式
        fot = '%(asctime)s - [%(filename)s-->line:%(lineno)d] - %(levelname)s: %(message)s'
        # 创建日志格式对象
        formatter = logging.Formatter(fot)
        # 输出格式绑定到输出渠道
        sh.setFormatter(formatter)
        fh.setFormatter(formatter)
        return my_log


# 创建一个日志收集器对象
log = MyLogging()

# log.debug('---这个是debug等级的日志，一般用于调试')
# log.info('---这个是info等级的日志，常规信息的输出')
# log.warning('---这个是warning等级的日志，警告信息')
# log.error('----这个是error等级的日志，错误信息')
# log.critical('---这个是critical等级的日志，严重的错误，程序要奔溃')
