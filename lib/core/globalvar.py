# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

# 作者：咚咚呛
# 全局参数管理模块


def init():
    global _global_dict
    _global_dict = {}


def set_value(name, value):
    _global_dict[name] = value


def get_value(name, def_value=None):
    try:
        return _global_dict[name]
    except KeyError:
        return def_value
