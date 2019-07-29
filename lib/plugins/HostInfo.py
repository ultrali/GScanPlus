# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

import socket
import platform
from lib.core.common import *


# 作者：咚咚呛
# 版本：v0.1
# 功能：获取本机信息

class HostInfo:
    def __init__(self):
        self.hostname = ""
        self.ip = ""
        self.version = ""
        self.time = ""
        self.host_info()
        self.get_host_ip()

    # 获取主机基本信息
    def host_info(self):
        self.hostname = platform.node()
        # self.hostname = socket.gethostname()
        self.version = platform.platform()
        self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def get_host_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            self.ip = s.getsockname()[0]
        finally:
            s.close()

    def run(self):
        print('\nGet Host Info...')
        print('Hostname: %s' % self.hostname)
        print('IP: %s' % self.ip)
        print('OS Version: %s' % self.version)
        print('HostTime: %s' % self.time)
        sys.stdout.flush()
        file_write('Get Host Info\nHostname：%s\nIP：%s\nOS Version: %s\nHostTime: %s\n' % (
            self.hostname, self.ip, self.version, self.time))


if __name__ == '__main__':
    a = HostInfo()
    print(a.hostname)
    print(a.ip)
    print(a.version)
    print(a.time)
