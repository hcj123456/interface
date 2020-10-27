#!/usr/bin/env python
#-*- coding:UTF-8 -*-
"""
=============================
author:'liudl'
time:2019/8/31
E-mail:liudl7@lenovo.com
=============================
"""
import requests
from requests import cookies


class HttpRequest(object):
    """不需要记住cookie信息的请求类"""

    def request(self, method, url, json=None, data=None, headers=None):
        # None 默认值，可传可不传
        # 发送请求的方法
        # 转换为小写
        method = method.lower()
        # 判断发送请求的方法
        if method == 'post':
            return requests.post(url=url, json=json, data=data, headers=headers)
        elif method == 'get':
            return requests.get(url=url, params=data, headers=headers, cookies=cookies)


class HttpSession(object):
    """使用session对象发送请求，自动记录cookies信息"""

    def __init__(self):
        # 创建一个session对象
        self.session = requests.session()

    def request(self, method, url, json=None, data=None, headers=None):
        # 判断请求方法
        method = method.lower()
        if method == 'post':
            return self.session.post(url=url, json=json, data=data, headers=headers)
        elif method == 'get':
            return self.session.get(url=url, params=data, headers=headers)

    def close(self):
        # 记得关闭session对象
        self.session.close()

if __name__ == '__main__':
    http = HttpSession()
    # response1 = http.request(method='get', url='http://test.lemonban.com/futureloan/mvc/api/member/login',
    #                          data={"mobilephone": "18750261519", "pwd": "123qwe"})
    # re = http.request(method='get', url='http://test.lemonban.com/futureloan/mvc/api/loan/add',
    #                   data={"memberId": "132694", "title": "世界这么大，想去看一看", "amount": 20000, "loanRate": "12.0",
    #                         "loanTerm": 2, "loanDateType": 0, "repaymemtWay": 11, "biddingDays": 5})
    # response = http.request(method='post', url='http://test.lemonban.com/futureloan/mvc/api/member/withdraw',
    #                         data={"mobilephone": "18750261519", "amount": 10000})
    # response2 = http.request(method='post', url='http://test.lemonban.com/futureloan/mvc/api/member/bidLoan',
    #                          data={"memberId": "132694", "password": "123qwe", "loanId": "85894",
    #                                "amount": 3000})

    # r = requests.post(url='https://open.ybj.fujian.gov.cn/api/gafe/rest?zyregion=350200', json={
    #                                                         "funid": "N07.08.03.03",
    #                                                         "data": {
    #                                                         "idcard": "350603199510110019"
    #                                                                 }
    #                                                                 })
    # response2 = http.request(method='post', url='https://open.ybj.fujian.gov.cn/api/gafe/rest?zyregion=350200',
    #                                                   json={
    #                                                         "funid": "N07.08.03.03",
    #                                                         "data": {
    #                                                         "idcard": "350603199510110019"
    #                                                                 }
    #                                                                 })
    # res = response2.json()
    # # res1 = re.json()
    # print(res)
