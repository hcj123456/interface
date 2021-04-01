#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/12/11 16:41
# software: PyCharm
import os
import random
import yaml
# @staticmethod
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
print(BASE_DIR)

def changeYamlConfig(path, key, value):
    with open(path, 'r', encoding='utf-8') as f:
        lines = []  # 创建了一个空列表，里面没有元素
        for line in f.readlines():
            if line != '\n':
                lines.append(line)
        f.close()
    with open(path, 'w', encoding='utf-8') as f:
        flag = 0
        for line in lines:
            if key in line and '#' not in line:
                leftstr = line.split(":")[0]
                newline = "{0}: {1}".format(leftstr,str(value).replace('\'','\"'))
                line = newline
                f.write('%s\n' % line)
                flag = 1
            else:
                f.write('%s' % line)
        f.close()
        return flag
file_path = os.path.dirname(os.path.dirname(__file__)) + os.sep + 'test_data' + os.sep + 'data.yml'
rr=changeYamlConfig(file_path,"tel","1582346%s"%(random.randint(0000,9999)))
print(rr)