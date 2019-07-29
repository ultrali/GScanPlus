# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.plugins.SSHAnalysis import *
from lib.core.common import *


# 作者：咚咚呛
# 版本：v0.1
# 功能：日志类安全分析

class LogAnalysis:
    def __init__(self):
        self.log_malware = []
        self.name = 'Log Audit'

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_wtmp(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/var/log/wtmp'):
                return suspicious, malice
            p = os.popen("who /var/log/wtmp 2>/dev/null | awk '{print $1\";;\"$3\";;\"$5}'")
            wtmp_infos = p.readlines()
            for wtmp_info in wtmp_infos:
                wtmp_info = wtmp_info.strip()
                if wtmp_info:
                    items = wtmp_info.split(";;")
                    if len(items) != 3:
                        continue
                    user, time_, ips = items
                    if not ips:
                        continue
                    if ips[0] != '(':
                        continue
                    ip = ips.replace('(', '').replace(')', '')
                    if check_ip(ip):
                        malice_result(self.name, 'wtmp login history check', '/var/log/wtmp', '',
                                      'overseas IP via user(%s) login: %s' % (user, ip),
                                      '[1]who /var/log/wtmp', 'Suspicious', time_, user,
                                      programme='passwd %s #Change user(%s) password' % (user, user))
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_utmp(self):
        suspicious, malice = False, False
        try:
            p = os.popen("who 2>/dev/null | awk '{print $1\";;\"$3\";;\"$5}'")
            utmp_infos = p.readlines()
            # p1 = Popen("who 2>/dev/null", stdout=PIPE, shell=True)
            # p2 = Popen("awk '{print $1\" \"$3\" \"$5}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            # utmp_infos = p2.stdout.read().splitlines()
            for utmp_info in utmp_infos:
                utmp_info = utmp_info.strip()
                if utmp_info:
                    items = utmp_info.split(';;')
                    if len(items) != 3:
                        continue
                    user, time_, ips = items
                    if ips[0] != '(':
                        continue
                    ip = ips.replace('(', '').replace(')', '')
                    if check_ip(ip):
                        malice_result(self.name, 'utmp login history check', '/run/utmp', '',
                                      'overseas IP via user(%s) login: %s' % (user, ip),
                                      '[1]who', 'Suspicious', time_, user,
                                      programme='passwd %s #Change user(%s) password' % (user, user))
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_lastlog(self):
        suspicious, malice = False, False
        if not os.path.exists('/var/log/lastlog'):
            return suspicious, malice
        try:
            # p1 = Popen("lastlog 2>/dev/null", stdout=PIPE, shell=True)
            # p2 = Popen("awk '{if (NR>1){print $1\" \"$3}}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            # lastlogs = p2.stdout.read().splitlines()
            p = os.popen("lastlog 2>/dev/null |awk '{if(NR>1) print $1\";;\"$3}'")
            lastlogs = p.readlines()
            for lastlog in lastlogs:
                lastlog = lastlog.strip()
                if lastlog:
                    if len(lastlog.split(';;')) != 2:
                        continue
                    user, ip = lastlog.split(';;')
                    if ip == "logged":
                        continue
                    if check_ip(ip):
                        malice_result(self.name, 'lastlog history login check', '/var/log/lastlog', '',
                                      'Overseas IP via user(%s) login: %s' % (user, ip),
                                      '[1]who', 'Suspicious', "", user,
                                      programme='passwd %s #Change user(%s) password' % (user, user))
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 排查secure SSH的爆破记录
    def check_sshlog(self):
        suspicious, malice = False, False
        try:
            correct_baopo_infos = SSHAnalysis(log_dir='/var/log/').correct_baopo_infos
            if len(correct_baopo_infos) > 0:
                for info in correct_baopo_infos:
                    user = info['user']
                    time_ = os.popen('date -d ' + info['time'] + " '+%Y-%m-%d %H:%M:%S' 2>/dev/null").readlines()
                    ip = info['ip']
                    malice_result(self.name, 'secure log check', '/var/log/secure', '',
                                  'SSH service was bruteforce, success login at time(%s), ip(%s) via user(%s)' % (
                                      time_, ip, user),
                                  '[1]cat /var/secure', 'Risk',
                                  time_, user, programme='passwd %s #Change user(%s) password' % (user, user))
                    malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nstart log audit...')
        file_write('\nstart log audit...\n')

        string_output(' [1]secure log')
        suspicious, malice = self.check_sshlog()
        result_output_tag(suspicious, malice)

        string_output(' [2]wtmp login history')
        suspicious, malice = self.check_wtmp()
        result_output_tag(suspicious, malice)

        string_output(' [3]utmp login history')
        suspicious, malice = self.check_utmp()
        result_output_tag(suspicious, malice)

        string_output(' [4]lastlog login history')
        suspicious, malice = self.check_lastlog()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    infos = LogAnalysis()
    infos.run()
