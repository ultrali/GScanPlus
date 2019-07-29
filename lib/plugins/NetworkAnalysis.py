# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 分析网络连接
# 1、检查当前网络对外连接，提取国外连接
# 2、检查当前对外连接，匹配Rootkit特征
# 3、网卡混杂模式

class NetworkAnalysis:
    def __init__(self):
        # 可疑网络连接列表
        # 远程ip、远程端口、可疑描述
        self.network_malware = []
        self.name = 'Network Security'
        self.port_malware = [
            {'protocol': 'tcp', 'port': '1524', 'description': 'Possible FreeBSD (FBRK) Rootkit backdoor'},
            {'protocol': 'tcp', 'port': '1984', 'description': 'Fuckit Rootkit'},
            {'protocol': 'udp', 'port': '2001', 'description': 'Scalper'},
            {'protocol': 'tcp', 'port': '2006', 'description': 'CB Rootkit or w00tkit Rootkit SSH server'},
            {'protocol': 'tcp', 'port': '2128', 'description': 'MRK'},
            {'protocol': 'tcp', 'port': '6666', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6667', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6668', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6669', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '7000', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '13000', 'description': 'Possible Universal Rootkit (URK) SSH server'},
            {'protocol': 'tcp', 'port': '14856', 'description': 'Optic Kit (Tux)'},
            {'protocol': 'tcp', 'port': '25000', 'description': 'Possible Universal Rootkit (URK) component'},
            {'protocol': 'tcp', 'port': '29812', 'description': 'FreeBSD (FBRK) Rootkit default backdoor port'},
            {'protocol': 'tcp', 'port': '31337', 'description': 'Historical backdoor port'},
            {'protocol': 'tcp', 'port': '32982', 'description': 'Solaris Wanuk'},
            {'protocol': 'tcp', 'port': '33369', 'description': 'Volc Rootkit SSH server (divine)'},
            {'protocol': 'tcp', 'port': '47107', 'description': 'T0rn'},
            {'protocol': 'tcp', 'port': '47018', 'description': 'Possible Universal Rootkit (URK) component'},
            {'protocol': 'tcp', 'port': '60922', 'description': 'zaRwT.KiT'},
            {'protocol': 'tcp', 'port': '62883',
             'description': 'Possible FreeBSD (FBRK) Rootkit default backdoor port'},
            {'protocol': 'tcp', 'port': '65535', 'description': 'FreeBSD Rootkit (FBRK) telnet port'}
        ]
        # self.check_network()

    # 境外IP的链接
    def check_network_abroad(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen(
                "netstat -anptu 2>/dev/null| grep ESTABLISHED | awk '{print $1\" \"$5\" \"$7}'").readlines()
            for nets in shell_process:
                netinfo = nets.strip().split(' ')
                protocol = netinfo[0]
                remote_ip, remote_port = netinfo[1].replace("\n", "").split(":")
                pid, pname = netinfo[2].replace("\n", "").split("/")
                if check_ip(remote_ip):
                    malice_result(self.name, 'Overseas IP network connections', '', pid,
                                  'process(%s) connect with overseas ip(%s) via protocol(%s)' % (
                                      pname, remote_ip, protocol),
                                  '[1]netstat -ano',
                                  'Suspicious', programme='kill %s #Close Suspicious Network Connections' % pid)
                    suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 可疑端口的链接
    def check_net_suspicious(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen(
                "netstat -anp 2>/dev/null| grep ESTABLISHED | awk '{print $1\" \"$5\" \"$7}'").readlines()
            for nets in shell_process:
                netinfo = nets.strip().split(' ')
                # protocol = netinfo[0]
                remote_ip, remote_port = netinfo[1].replace("\n", "").split(":")
                pid, pname = netinfo[2].replace("\n", "").split("/")
                for malware in self.port_malware:
                    if malware['port'] == remote_port:
                        malice_result(self.name, 'Connect Suspicious Port', '', pid,
                                      'process(%s) connect remote ip(%s) via suspicious port(%s), '
                                      'this port is ofen used to: %s' % (
                                          pname, remote_ip, remote_port, malware['description']),
                                      '[1]netstat -ano', 'Suspicious',
                                      programme='kill %s #Close Suspicious Process' % pid)
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 网卡混杂模式检测
    def check_promisc(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen("ifconfig 2>/dev/null| grep PROMISC | grep RUNNING").readlines()
            if len(shell_process) > 0:
                malice_result(self.name, 'NIC PROMISC mode', '', '', 'NIC PROMISC mode is actived',
                              'ifconfig | grep PROMISC | grep RUNNING',
                              'Suspicious', programme='ifconfig eth0 -promisc #Close NIC PROMISC mode')
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nStart Network Security Check...')
        file_write('\nStart Network Security Check...\n')

        string_output(' [1]connect to remote')
        suspicious, malice = self.check_network_abroad()
        result_output_tag(suspicious, malice)

        string_output(' [2]malicious network connection')
        suspicious, malice = self.check_net_suspicious()
        result_output_tag(suspicious, malice)

        string_output(' [3]NIC PROMISC mode')
        suspicious, malice = self.check_promisc()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    infos = NetworkAnalysis()
    infos.run()
    print("Suspicious Network Connections: ")
    for info in infos.network_malware:
        print(info)
