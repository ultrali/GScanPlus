# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 配置安全类检测
# 1、dns配置检测
# 2、防火墙配置检测
# 3、hosts配置检测

class ConfigAnalysis:
    def __init__(self):
        self.config_suspicious = []
        self.ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.name = 'Configuration Risk'

    # 检测dns设置
    def check_dns(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/resolv.conf'):
                shell_process = os.popen(
                    'cat /etc/resolv.conf 2>/dev/null| grep -E -o "([0-9]{1,3}[\\.]){3}[0-9]{1,3}"').readlines()
                for ip in shell_process:
                    ip = ip.strip()
                    if not check_ip(ip):
                        continue
                    if ip == '8.8.8.8' or ip == "114.114.114.114":
                        continue
                    malice_result(self.name, 'DNS security configure', '/etc/resolv.conf', '',
                                  'DNS is set to overseas IP: %s' % ip,
                                  '[1]cat /etc/resolv.conf', 'Suspicious',
                                  programme='vi /etc/resolv.conf #Change DNS configure')
                    suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 检测防火墙设置
    def check_iptables(self):
        suspicious, malice = False, False
        if not os.path.exists('/etc/sysconfig/iptables'):
            return suspicious, malice
        for line in open('/etc/sysconfig/iptables'):
            if len(line) < 5:
                continue
            if line[0] != '#' and 'ACCEPT' in line:
                malice_result(self.name, 'iptables security configure', '/etc/sysconfig/iptables', '',
                              'iptables ACCEPT policy: %s' % line, '[1]cat /etc/sysconfig/iptables',
                              'Suspicious',
                              programme='vi /etc/sysconfig/iptables #Change/Delete this ACCEPT policy')
                suspicious = True
        return suspicious, malice

    # 检测hosts配置信息
    def check_hosts(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists("/etc/hosts"):
                return suspicious, malice
            hosts = os.popen("cat /etc/hosts 2>/dev/null |grep -Ev ^#| awk '{print $1}'").readlines()
            for ip_info in hosts:
                if not re.search(self.ip_re, ip_info):
                    continue
                if not check_ip(ip_info.strip().replace('\n', '')):
                    continue
                malice_result(self.name, 'HOSTS security configure', '/etc/hosts', '', 'overseas IP: %s' % ip_info,
                              '[1]cat /etc/hosts', 'Suspicious',
                              programme='vi /etc/hosts #Delete/Change overseas hosts configure')
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nConfiguration Risk security scan...')
        file_write('\nConfiguration Risk security scan...\n')

        string_output(' [1]DNS configure')
        suspicious, malice = self.check_dns()
        result_output_tag(suspicious, malice)

        string_output(' [2]iptables')
        suspicious, malice = self.check_iptables()
        result_output_tag(suspicious, malice)

        string_output(' [3]hosts file')
        suspicious, malice = self.check_hosts()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    infos = ConfigAnalysis()
    infos.run()
