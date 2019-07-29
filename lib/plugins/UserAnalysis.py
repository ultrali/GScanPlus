# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 版本：v0.1
# 账户类安全排查
# 1、查看root权限账户，排除root本身
# 2、查看系统中是否存在空口令账户
# 3、查看sudoers文件权限，是否存在可直接sudo获取root的账户
# 4、查看各账户下登录公钥
# 5、密码文件权限检测

class UserAnalysis:
    def __init__(self):
        self.user_malware = []
        self.name = 'Account Security'

    # 检测root权限用户
    def check_user(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen("awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null").readlines()
            for user in shell_process:
                if user.replace("\n", "") != 'root':
                    malice_result(self.name, 'root security check', '/etc/passwd', '',
                                  'found privileged accounts: %s' % user.replace("\n", ""),
                                  '[1]cat /etc/passwd', 'Suspicious',
                                  programme='vi /etc/passwd #Revoke account root privileges.')
                    suspicious = False
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 检测空口令账户
    def check_empty(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/shadow'):
                shell_process2 = os.popen(
                    "awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null").readlines()
                for user in shell_process2:
                    malice_result(self.name, 'empty password account', '/etc/shadow', '',
                                  'found empty password account: %s' % user.replace("\n", ""),
                                  '[1]cat /etc/shadow', 'Risk',
                                  programme='userdel %s #Delete this account' % user.replace("\n", ""))
                    malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 检测sudo权限异常账户
    def check_sudo(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/sudoers'):
                shell_process3 = os.popen(
                    "cat /etc/sudoers 2>/dev/null |grep -v '#'|grep 'ALL=(ALL)'|awk '{print $1}'").readlines()
                for user in shell_process3:
                    if user.replace("\n", "") != 'root' and user[0] != '%':
                        malice_result(self.name, 'sudoers scan', '/etc/sudoers', '',
                                      'user(%s) can get root privileges by sudo' % user.replace("\n", ""),
                                      '[1]cat /etc/sudoers', 'Risk',
                                      programme='vi /etc/sudoers #Change sudo settings')
                        suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 获取用户免密登录的公钥
    def check_authorized_keys(self):
        suspicious, malice = False, False
        try:
            for dir_name in os.listdir('/home/'):
                suspicious2, malice2 = self.file_analysis(
                    os.path.join('%s%s%s' % ('/home/', dir_name, '/.ssh/authorized_keys')),
                    dir_name)
                if suspicious2:
                    suspicious = True
                if malice2:
                    malice = True
            suspicious2, malice2 = self.file_analysis('/root/.ssh/authorized_keys', 'root')
            if suspicious2:
                suspicious = True
            if malice2:
                malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 分析authorized_keys文件
    def file_analysis(self, file, user):
        suspicious, malice = False, False
        try:
            if os.path.exists(file):
                shell_process = os.popen("awk '{print $3}' %s 2> /dev/null" % file).readlines()
                if len(shell_process):
                    authorized_key = ' & '.join(shell_process)
                    malice_result(self.name, 'ssh authorized_keys', file, '',
                                  'user(%s) can login via ssh authorized_keys(%s), client hostname: %s' % (
                                      user, file, authorized_key),
                                  '[1]cat %s' % file, 'Suspicious',
                                  programme='vi %s #delete suspicious authorized_keys' % file)
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 密码文件检测
    def passwd_file_analysis(self):
        suspicious, malice = False, False
        try:
            files = ['/etc/passwd', '/etc/shadow']
            for file in files:
                if not os.path.exists(file):
                    continue
                shell_process = os.popen("ls -l " + file + " 2>/dev/null |awk '{print $1}'").readlines()
                if len(shell_process) != 1:
                    continue
                if file == '/etc/passwd' and shell_process[0].find('-rw-r--r--') == -1:
                    malice_result(self.name, 'passwd file', file, '',
                                  'passwd file permissions changed(not is -rw-r--r--)',
                                  'ls -l /etc/passwd', 'Suspicious')
                    suspicious = True
                elif file == '/etc/shadow' and shell_process[0].find('----------') == -1:
                    malice_result(self.name, 'shadow file', file, '',
                                  'shadow file permissions changed(not is ----------)',
                                  'ls -l /etc/shadow', 'Suspicious')
                    suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nAccount Security scan...')
        file_write('\nAccount Security scan...\n')

        string_output(' [1]root security')
        suspicious, malice = self.check_user()
        result_output_tag(suspicious, malice)

        string_output(' [2]empty password account')
        suspicious, malice = self.check_empty()
        result_output_tag(suspicious, malice)

        string_output(' [3]sudoers')
        suspicious, malice = self.check_sudo()
        result_output_tag(suspicious, malice)

        string_output(' [4]ssh authorized_keys')
        suspicious, malice = self.check_authorized_keys()
        result_output_tag(suspicious, malice)

        string_output(' [5]passwd-shadow file')
        suspicious, malice = self.passwd_file_analysis()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    infos = UserAnalysis()
    infos.run()
    print("Suspicious Account: ")
    for info in infos.user_malware:
        print(info)
