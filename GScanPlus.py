# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.option import *
import os

# 作者：咚咚呛
# 版本：v0.1
# 功能：本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧安全Checklist的自动化，用于快速主机安全点排查。

# author: ultrali
# version: v10.1
# update:
# 1. 去掉宽泛大量的Exception忽略
# 2. 错误逻辑修改
# 3. 效率提升
# running env:
# python > 2.6.0
# test with python 2.7.5/3.6.8 on centos7
# python 2.6.6 on centos6


if __name__ == '__main__':
    version = 'v10.1'
    progam = u'''
  _______      _______.  ______      ___      .__   __. 
 /  _____|    /       | /      |    /   \     |  \ |  |    {version:%s}
|  |  __     |   (----`|  ,----'   /  ^  \    |   \|  | 
|  | |_ |     \   \    |  |       /  /_\  \   |  . `  |    {author:咚咚呛}
|  |__| | .----)   |   |  `----. /  _____  \  |  |\   | 
 \______| |_______/     \______|/__/     \__\ |__| \__|    http://grayddq.top


    ''' % version
    print(progam)

    main(os.path.dirname(os.path.abspath(__file__)))
