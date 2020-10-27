#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:huangCijin
# datetime:2020/9/24 15:48
# software: PyCharm
import re

from common.conifg import myconf

"""
实现思路：
1、获取用例数据
2、判断该条用例数据是否有需要替换的数据
3、对数据进行替换
"""


# 通过search方法进行匹配
# 判断是否有匹配到数据

class ConText:
    """用来（临时）保存接口之间以来参数的类"""
    pass


def data_replace(data):
    """替换动态参数"""
    while re.search(r"#(.+?)#", data):
        res = re.search(r"#(.+?)#", data)
        # 提取要替换的内容
        r_data = res.group()
        # 获取要替换的字段
        key = res.group(1)
        # 去配置文件中读取字段对应得数据
        try:
            value = myconf.get('data', key)
        except:
            value = getattr(ConText, key)
        # 进行替换
        data = re.sub(r_data, str(value), data)

    return data


if __name__ == '__main__':
    # 给对象设置一个属性：对象（类），属性名    属性值
    setattr(ConText, "memberid", 1999)
    # print(ConText.memberid)
    # 获取对象的属性：对象 属性名
    id = getattr(ConText, 'memberid')
    print(id)

# if __name__ == '__main__':
#     s = '{"mobilephone": "#phone#","pwd":"#pwd#"}'
#     s2 = data_replace(s)
#     print(s2)
