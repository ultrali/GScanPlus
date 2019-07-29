# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.plugins.FileCheck import *


# 作者：咚咚呛
# 分析主机文件类异常
# 1、系统可执行文件hash对比
# 2、系统可执行文件扫描
# 3、临时目录文件扫描
# 4、用户目录文件扫描
# 5、可疑隐藏文件扫描

class FileAnalysis:
    def __init__(self):
        # 恶意文件列表
        self.file_malware = []
        self.name = 'File Security'

    def check_system_hash(self):
        suspicious, malice = False, False
        file_infos = FileCheck().file_malware
        if len(file_infos) > 15:
            return suspicious, malice
        for infom in file_infos:
            if infom['action'] == 'Create':
                malware = 'create file(%s), filename is sensitive, not recorded in current hash database. ' \
                          'hash：%s' % (infom['file'], infom['newMD5'])
            else:
                malware = 'modified important executable file(%s), hash: %s' % (infom['file'], infom['newMD5'])
            malice_result(self.name, 'important system file hash check', infom['file'], '', malware,
                          '[1]strings %s [2] cat %s' % (infom['file'], infom['file']), 'Risk',
                          programme='rm %s #delete malicious file.' % infom['file'])
            malice = True
        return suspicious, malice

    # 由于速度的问题，故只检测指定重要文件
    def check_system_integrity(self):
        suspicious, malice = False, False

        system_file = ["depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip", "lsmod",
                       "modinfo", "modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel", "sulogin", "sysctl",
                       "awk", "basename", "bash", "cat", "chmod", "chown", "cp", "cut", "date", "df", "dmesg", "echo",
                       "egrep", "env", "fgrep", "find", "grep", "kill", "logger", "login", "ls", "mail", "mktemp",
                       "more", "mount", "mv", "netstat", "ping", "ps", "pwd", "readlink", "rpm", "sed", "sh", "sort",
                       "su", "touch", "uname", "gawk", "mailx", "adduser", "chroot", "groupadd", "groupdel", "groupmod",
                       "grpck", "lsof", "pwck", "sestatus", "sshd", "useradd", "userdel", "usermod", "vipw", "chattr",
                       "curl", "diff", "dirname", "du", "file", "groups", "head", "id", "ipcs", "killall", "last",
                       "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep", "pkill",
                       "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "size", "ssh",
                       "stat", "strace", "strings", "sudo", "tail", "test", "top", "tr", "uniq", "users", "vmstat", "w",
                       "watch", "wc", "wget", "whereis", "which", "who", "whoami", "test"]

        binary_list = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        for d in binary_list:
            if not os.path.exists(d):
                continue
            for file in gci(d):
                filename = os.path.basename(file)
                if filename not in system_file:
                    continue
                malware = analysis_file(file)
                if malware:
                    malice_result(self.name, 'System executable file scan', file, '', malware,
                                  '[1]rpm -qa %s [2]strings %s' % (file, file), 'Risk',
                                  programme='rm %s #delete malicious file.' % file)
                    malice = True
        return suspicious, malice

    # 检查所有临时目录文件
    def check_tmp(self):
        suspicious, malice = False, False
        tmp_list = ['/tmp/', '/var/tmp/', '/dev/shm/']
        for d in tmp_list:
            if not os.path.exists(d):
                continue
            for file in gci(d):
                malware = analysis_file(file)
                if malware:
                    malice_result(self.name, 'Temporary directory scan', file, '', malware,
                                  '[1]rpm -qa %s [2]strings %s' % (file, file), 'Risk',
                                  programme='rm %s #delete malicious file.' % file)
                    malice = True
        return suspicious, malice

    # 检查所有用户目录文件
    def check_user_dir(self):
        suspicious, malice = False, False
        dir_list = ['/home/', '/root/']
        for d in dir_list:
            if not os.path.exists(d):
                continue
            for file in gci(d):
                malware = analysis_file(file)
                if malware:
                    malice_result(self.name, 'Home directory scan', file, '', malware,
                                  '[1]rpm -qa %s [2]strings %s' % (file, file), 'Risk',
                                  programme='rm %s #delete malicious file.' % file)
                    malice = True
        return suspicious, malice

    # 可疑文件扫描
    def check_hide(self):
        suspicious, malice = False, False
        try:
            infos = os.popen(
                'find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" '
                '! -path "/private/*" -name "..*" 2>/dev/null').readlines()
            for file in infos:
                file = file.strip()
                malice_result(self.name, 'Suspicious hidden file scan', file, '',
                              "file(%s) is a suspicious hidden file." % file,
                              '[1]ls -l %s [2]strings %s' % (file, file), 'Suspicious',
                              programme='rm %s #delete malicious file.' % file)
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nFile Security Scan...')
        file_write('\nFile Security Scan...\n')

        string_output(' [1]Important system file hash')
        suspicious, malice = self.check_system_hash()
        result_output_tag(suspicious, malice)

        string_output(' [2]System executable file')
        suspicious, malice = self.check_system_integrity()
        result_output_tag(suspicious, malice)

        string_output(' [3]Temporary directory')
        suspicious, malice = self.check_tmp()
        result_output_tag(suspicious, malice)

        string_output(' [4]Home directory')
        suspicious, malice = self.check_user_dir()
        result_output_tag(suspicious, malice)

        string_output(' [5]Suspicious hidden file')
        suspicious, malice = self.check_hide()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    # File_Analysis().run()
    info = FileAnalysis()
    info.run()
