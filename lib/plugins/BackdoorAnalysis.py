# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 常规类后门检测
# 动态库加载顺序：LD_PRELOAD>LD_LIBRARY_PATH>/etc/ld.so.cache>/lib>/usr/lib
# 1、LD_PRELOAD后门检测
# 2、LD_AOUT_PRELOAD后门检测
# 3、LD_ELF_PRELOAD后门检测
# 4、LD_LIBRARY_PATH后门检测
# 5、ld.so.preload后门检测
# 6、PROMPT_COMMAND后门检测
# 7、cron后门检测
# 8、alias后门
# 9、ssh后门 ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
# 10、SSH Server wrapper 后门，替换/user/sbin/sshd 为脚本文件
# 11、/etc/inetd.conf 后门
# 12、/etc/xinetd.conf/后门
# 13、setuid类后门
# 14、/etc/fstab类后门（待写）
# 13、系统启动项后门检测


class BackdoorAnalysis:
    def __init__(self):
        # 异常后门列表
        self.backdoor = []

    # 检测配置文件是否存在恶意配置
    @staticmethod
    def check_conf(tag, file, mode='only'):
        try:
            if not os.path.exists(file):
                return ""
            if os.path.isdir(file):
                return ""
            if mode == 'only':
                for line in open(file):
                    if len(line) < 3:
                        continue
                    if line[0] == '#':
                        continue
                    if 'export ' + tag in line:
                        return line
            else:
                return analysis_file(file)
            return ""
        except Exception as e:
            app_logger.error(str(e))
            return ""

    # 检测所有环境变量，是否存在恶意配置
    def check_tag(self, name, tag, mode='only'):
        suspicious, malice = False, False
        try:
            files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/root/.tcshrc',
                     '/etc/bashrc', '/etc/profile', '/etc/profile.d/', '/etc/csh.login', '/etc/csh.cshrc']
            home_files = ['/.bashrc', '/.bash_profile', '/.tcshrc', '/.cshrc', '/.tcshrc']

            # 循环用户目录查看环境设置
            for d in os.listdir('/home/'):
                for home_file in home_files:
                    if not os.path.isdir(d):
                        continue
                    file = os.path.join('%s%s%s' % ('/home/', d, home_file))
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result('Normal Backdoor Check', name, file, '', info,
                                      '[1]echo $%s [2]cat %s' % (tag, file), 'Suspicious',
                                      programme='vi %s #delete settings(%s)' % (file, tag))
                        suspicious = True
            # 检查系统目录的配置
            for file in files:
                # 如果为目录形式，则遍历目录下所有文件
                if os.path.isdir(file):
                    for f in gci(file):
                        info = self.check_conf(tag, f, mode)
                        if info:
                            malice_result('Normal Backdoor Check', name, f, '', info,
                                          '[1]echo $%s [2]cat %s' % (tag, f),
                                          'Suspicious')
                            suspicious = True
                else:
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result('Normal Backdoor Check', name, file, '', info,
                                      '[1]echo $%s [2]cat %s' % (tag, file), 'Suspicious',
                                      programme='vi %s #delete settings(%s)' % (file, tag))
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # LD_PRELOAD后门检测
    def check_LD_PRELOAD(self):
        suspicious, malice = self.check_tag('LD_PRELOAD Backdoor', 'LD_PRELOAD')
        return suspicious, malice

    # LD_AOUT_PRELOAD后门检测
    def check_LD_AOUT_PRELOAD(self):
        suspicious, malice = self.check_tag('LD_AOUT_PRELOAD Backdoor', 'LD_AOUT_PRELOAD')
        return suspicious, malice

    # LD_ELF_PRELOAD后门检测
    def check_LD_ELF_PRELOAD(self):
        suspicious, malice = self.check_tag('LD_ELF_PRELOAD Backdoor', 'LD_ELF_PRELOAD')
        return suspicious, malice

    # LD_LIBRARY_PATH后门检测
    def check_LD_LIBRARY_PATH(self):
        suspicious, malice = self.check_tag('LD_LIBRARY_PATH Backdoor', 'LD_LIBRARY_PATH')
        return suspicious, malice

    # PROMPT_COMMAND后门检测
    def check_PROMPT_COMMAND(self):
        # PROMPT_COMMAND，在显示命令提示符前执行该命令
        suspicious, malice = self.check_tag('PROMPT_COMMAND Backdoor', 'PROMPT_COMMAND')
        return suspicious, malice

    def check_export(self):
        # 未知环境变量
        suspicious, malice = self.check_tag('Unknown-environment-variable Backdoor', 'PATH', mode='all')
        return suspicious, malice

    @staticmethod
    def check_ld_so_preload():
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/ld.so.preload'):
                return suspicious, malice
            for line in open('/etc/ld.so.preload'):
                if not len(line) > 3:
                    continue
                if line[0] != '#':
                    content = analysis_strings(line)
                    if content:
                        malice_result('Normal Backdoor Check', 'ld.so.preload Backdoor', '/etc/ld.so.preload',
                                      '', content,
                                      '[1]cat /etc/ld.so.preload', 'Risk',
                                      programme='vi ld.so.preload #delete all so settings')
                        malice = True
            return suspicious, malice
        except IOError as e:
            app_logger.debug("read ld.so file failed: %s" % str(e))
        except Exception as e:
            app_logger.error(str(e))
        finally:
            return suspicious, malice

    @staticmethod
    def check_cron():
        suspicious, malice = False, False
        try:
            cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/',
                             '/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron in cron_dir_list:
                for file in gci(cron):
                    if not os.path.exists(file):
                        continue
                    if os.path.isdir(file):
                        continue
                    for i in open(file, 'r'):
                        content = analysis_strings(i)
                        if content:
                            malice_result('Normal Backdoor Check', 'cron Backdoor', file, '', content,
                                          '[1]cat %s' % file, 'Risk',
                                          programme='vi %s #Delete crontab task' % file)
                            malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    @staticmethod
    def check_ssh():
        suspicious, malice = False, False
        try:
            list_of_info = os.popen(
                "netstat -ntpl 2>/dev/null |grep ':22 '| awk '{if (NR>2){print $7}}'").read().splitlines()
            for info in list_of_info:
                info = info.strip()
                pid = info.split("/")[0]
                if os.path.exists('/proc/%s/exe' % pid):
                    if 'sshd' in os.readlink('/proc/%s/exe' % pid):
                        malice_result('Normal Backdoor Check', 'SSH Backdoor', '/porc/%s/exe' % pid, pid,
                                      "Non-port-22 SSH service",
                                      '[1]ls -l /porc/%s [2]ps -ef|grep %s|grep -v grep' % (pid, pid), 'Risk',
                                      programme='kill %s #kill abnormal sshd process' % pid)
                        malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    @staticmethod
    def check_ssh_wrapper():
        suspicious, malice = False, False
        try:
            list_of_info = os.popen("file /usr/sbin/sshd 2>/dev/null").readlines()
            if not len(list_of_info):
                return suspicious, malice
            if ('ELF' not in list_of_info[0]) and ('executable' not in list_of_info[0]):
                malice_result('Normal Backdoor Check', 'SSHwrapper Backdoor', '/usr/sbin/sshd', "",
                              "/usr/sbin/sshd has been tampered. That is not an executable file",
                              '[1]file /usr/sbin/sshd [2]cat /usr/sbin/sshd', 'Risk',
                              programme='rm /usr/sbin/sshd & yum -y install openssh-server & service sshd start '
                                        '#delete abnormal sshd files, and reinstall ssh service')
                malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    @staticmethod
    def check_inetd():
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/inetd.conf'):
                return suspicious, malice
            for line in open('/etc/inetd.conf'):
                content = analysis_strings(line)
                if content:
                    malice_result('Normal Backdoor Check', 'inetd.conf Backdoor', '/etc/inetd.conf', '', content,
                                  '[1]cat /etc/inetd.conf', 'Risk',
                                  programme='vi /etc/inetd.conf #delete abnormal item')
                    malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    @staticmethod
    def check_xinetd():
        suspicious, malice = False, False
        try:
            conf_file_list = list()
            if os.path.exists('/etc/xinetd.conf/'):
                for file in os.listdir('/etc/xinetd.conf/'):
                    full_path = '/etc/xinetd.conf/' + file
                    if os.path.isfile(full_path):
                        # Subdirectory profile does not take effect.
                        conf_file_list.append(full_path)
            if os.path.exists('/etc/xinetd.d/'):
                for file in os.listdir('/etc/xinetd.d/'):
                    full_path = '/etc/xinetd.d/' + file
                    if os.path.isfile(full_path):
                        # Subdirectory profile does not take effect.
                        conf_file_list.append(full_path)
            if not conf_file_list:
                return False, False
            for conf_file in conf_file_list:
                for line in open(conf_file):
                    content = analysis_strings(line)
                    if content:
                        malice_result('Normal Backdoor Check', 'xinetd.conf Backdoor', conf_file,
                                      '', content,
                                      '[1]cat ' + conf_file, 'Risk',
                                      programme='vi %s #delete abnormal' % conf_file)
                        malice = True
                return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # setuid backdoor
    @staticmethod
    def check_setuid():
        suspicious, malice = False, False
        try:
            file_infos = os.popen(
                "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null | "
                "grep -vE 'pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|"
                "passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|"
                "nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'"
            ).readlines()
            for info in file_infos:
                malice_result('Normal Backdoor Check', 'setuid Backdoor', info, '',
                              'File(%s) has "setuid" attribute' % info, '[1]ls -l %s' % info, 'Risk',
                              programme='chmod u-s %s #delete "setuid" attribute' % info)
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.critical("Unexpected error: %s" % str(e))
            return suspicious, malice

    # system startup
    @staticmethod
    def check_startup():
        suspicious, malice = False, False
        init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local', '/usr/local/etc/rc.d',
                     '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab', '/etc/systemd/system']
        for path in init_path:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                content = analysis_file(path)
                if content:
                    malice_result('Normal Backdoor Check', 'Startup Backdoor', path, '', content,
                                  '[1]cat %s' % path, 'Risk',
                                  programme='vi %s #Delete abnormal item' % path)
                    malice = True
                continue
            for file in gci(path):
                content = analysis_file(file)
                if content:
                    malice_result('Normal Backdoor Check', 'Startup Backdoor', path, '', content,
                                  '[1]cat %s' % path, 'Risk',
                                  programme='vi %s #Delete abnormal item' % path)
                    malice = True
        return suspicious, malice

    def run(self):
        print('\nBackdoor Security Scan...')
        file_write('\nBackdoor Security Scan...\n')

        string_output(' [1]LD_PRELOAD')
        suspicious, malice = self.check_LD_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(' [2]LD_AOUT_PRELOAD')
        suspicious, malice = self.check_LD_AOUT_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(' [3]LD_ELF_PRELOAD')
        suspicious, malice = self.check_LD_ELF_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(' [4]LD_LIBRARY_PATH')
        suspicious, malice = self.check_LD_LIBRARY_PATH()
        result_output_tag(suspicious, malice)

        string_output(' [5]ld.so.preload')
        suspicious, malice = self.check_ld_so_preload()
        result_output_tag(suspicious, malice)

        string_output(' [6]PROMPT_COMMAND')
        suspicious, malice = self.check_PROMPT_COMMAND()
        result_output_tag(suspicious, malice)

        string_output(' [7]cron')
        suspicious, malice = self.check_cron()
        result_output_tag(suspicious, malice)

        string_output(' [8]Unknown-environment-variable')
        suspicious, malice = self.check_export()
        result_output_tag(suspicious, malice)

        string_output(' [9]ssh')
        suspicious, malice = self.check_ssh()
        result_output_tag(suspicious, malice)

        string_output(' [10]SSH wrapper')
        suspicious, malice = self.check_ssh_wrapper()
        result_output_tag(suspicious, malice)

        string_output(' [11]inetd.conf')
        suspicious, malice = self.check_inetd()
        result_output_tag(suspicious, malice)

        string_output(' [12]xinetd.conf')
        suspicious, malice = self.check_xinetd()
        result_output_tag(suspicious, malice)

        string_output(' [13]setuid')
        suspicious, malice = self.check_setuid()
        result_output_tag(suspicious, malice)

        string_output(' [14]Startup')
        suspicious, malice = self.check_startup()
        result_output_tag(suspicious, malice)

        result_output_file('Normal Backdoor Check')


if __name__ == '__main__':
    infos = BackdoorAnalysis()
    infos.run()
