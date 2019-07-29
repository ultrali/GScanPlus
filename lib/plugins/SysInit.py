# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 系统初始化检测
# 1、文件alias配置检测


class SysInit:
    def __init__(self):
        self.backdoor_info = []
        self.name = 'System Initialization'

    def check_alias_conf(self):
        suspicious, malice = False, False
        files = ['/root/.bashrc', '/root/.bash_profile', '/etc/bashrc', '/etc/profile']

        for dirname in os.listdir('/home/'):
            suspicious2, malice2 = self.alias_file_analysis(
                os.path.join('%s%s%s' % ('/home/', dirname, '/.bashrc')))
            if suspicious2:
                suspicious = True
            if malice2:
                malice = True

            suspicious2, malice2 = self.alias_file_analysis(
                os.path.join('%s%s%s' % ('/home/', dirname, '/.bash_profile')))
            if suspicious2:
                suspicious = True
            if malice2:
                malice = True

        for file in files:
            suspicious2, malice2 = self.alias_file_analysis(file)
            if suspicious2:
                suspicious = True
            if malice2:
                malice = True

        return suspicious, malice

    # 分析环境变量alias配置文件的信息
    def alias_file_analysis(self, file):
        suspicious, malice = False, False
        # 程序需要用到的系统命令
        syscmds = ['ps', 'strings', 'netstat', 'find', 'echo', 'iptables', 'lastlog', 'who', 'ifconfig']
        if not os.path.exists(file):
            return suspicious, malice
        for line in open(file):
            if line[:5] == 'alias':
                for syscmd in syscmds:
                    if 'alias ' + syscmd + '=' in line:
                        malice_result(self.name, 'alise initialization',
                                      file, '', 'suspicious alias: %s' % line,
                                      '[1]alias [2]cat %s' % file, 'Suspicious',
                                      programme='vi %s #delete suspicious alias configure' % file)
                        suspicious = True
        return suspicious, malice

    def run(self):
        print('\nSystem Initialization check...')
        file_write('\nSystem Initialization check...\n')

        string_output(' [1]command alias')
        suspicious, malice = self.check_alias_conf()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    init = SysInit()
    init.run()
