#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/11/5 9:09
# software: PyCharm
import os
import yaml
class Read_Yaml_Data(object):
    # def __init__(self,data):
    #     self.data=data;
    def ret_yaml_data(self,file_name,name):
        cases = []
        file_path = os.path.dirname(os.path.dirname(__file__)) + os.sep + 'test_data' + os.sep + file_name + '.yml'
        f = open(file_path, 'r', encoding='utf-8')
        data = yaml.load(f, Loader=yaml.FullLoader).get(name)
        titles = []
        for i in data.keys():
            titles.append(i)
        case = []
        for i in data.values():
            case.append(i)
        zip_data = zip(titles, case)
        # print(list(zip_data))
        case_data = list(zip_data)
        return case_data
# tt = Read_Yaml_Data().ret_yaml_data('data','Search_data1')
# print(tt)
