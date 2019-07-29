# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
from lib.core.common import *

# author：  咚咚呛
# 对系统重要文件夹进行监控，并把修改、创建的文件进行日志打印，
# 排除prelink服务对二进制文件修改对结果进行干扰，每次排查都会排除prelink的操作


class FileCheck:
    def __init__(self):
        # 异常文件列表
        self.file_malware = []
        self.CHECK_DIR = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        # 是否只针对特定文件进行监控
        self.HIGH_FILTER = True
        # 监控文件内容列表
        self.HEIGH_FILE_ALARM = ["depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip",
                                 "lsmod", "modinfo", "modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel",
                                 "sulogin", "sysctl", "awk", "basename", "bash", "cat", "chmod", "chown", "cp", "cut",
                                 "date", "df", "dmesg", "echo", "egrep", "env", "fgrep", "find", "grep", "kill",
                                 "logger", "login", "ls", "mail", "mktemp", "more", "mount", "mv", "netstat", "ping",
                                 "ps", "pwd", "readlink", "rpm", "sed", "sh", "sort", "su", "touch", "uname", "gawk",
                                 "mailx", "adduser", "chroot", "groupadd", "groupdel", "groupmod", "grpck", "lsof",
                                 "pwck", "sestatus", "sshd", "useradd", "userdel", "usermod", "vipw", "chattr", "curl",
                                 "diff", "dirname", "du", "file", "groups", "head", "id", "ipcs", "killall", "last",
                                 "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep",
                                 "pkill", "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
                                 "sha512sum", "size", "ssh", "stat", "strace", "strings", "sudo", "tail", "test", "top",
                                 "tr", "uniq", "users", "vmstat", "w", "watch", "wc", "wget", "whereis", "which", "who",
                                 "whoami", "test"]
        # 系统执行路径
        self.SYS_PATH = get_value('SYS_PATH')
        self.HASH_DB = get_value('SYS_PATH') + '/db/hash_db.txt'
        # prelink服务会修改二进制文件，此处保存prelink服务的相关日志路径
        self.PRELINK_LOG_PATH = ['/var/log/prelink/prelink.log', '/var/log/prelink.log']

        # 开始进行扫描
        self.check_dir_hash()

    @staticmethod
    def get_file_hash(file_path):
        try:
            md5obj = hashlib.md5()
            size = 102400
            fp = open(file_path, 'rb')
            while True:
                content = fp.read(size)
                if not content:
                    break
                md5obj.update(content)
            fp.close()
            return md5obj.hexdigest()
        except Exception as e:
            app_logger.error(str(e))
            return None

    def get_dir_hash(self, path):
        """
        Get all file hash in a directory.
        :param path:
        :return: {file_full_path: hash}
        """
        hash_list_content = dict()
        for root, dirs, files in os.walk(path, topdown=True):
            for filename in files:
                full_path = os.path.join(root, filename)
                if not os.path.exists(full_path):
                    # Soft link corresponding file does not exist
                    continue
                if self.HIGH_FILTER and filename not in self.HEIGH_FILE_ALARM:
                    continue
                else:
                    if filename in self.HEIGH_FILE_ALARM:
                        file_hash = self.get_file_hash(full_path)
                        if file_hash:
                            hash_list_content[full_path] = file_hash
        return hash_list_content

    def get_history_hash_list(self):
        """
        get history file hash
        :return: {full_path: hash}
        """
        if not os.path.exists(self.HASH_DB):
            self.write_hash_db("Initialization")
            return "", ""
        if os.path.getsize(self.HASH_DB) == 0:
            self.write_hash_db("Initialization")
            return "", ""
        # {full_path: hash}
        history_hash_list_content = dict()
        # [full_path]
        history_file_path_list = []
        for line in open(self.HASH_DB):
            if (line != "") or (line is not None):
                full_path = line.split('||')[0].split('\n')[0]
                hash_vaule = line.split('||')[1].split('\n')[0]
                history_hash_list_content[full_path] = hash_vaule
                history_file_path_list.append(full_path)
        return history_hash_list_content, history_file_path_list

    # 写hash数据文件
    # 传入参数为操作类型，
    # Initialization为初始化hash文件，
    # Coverage为文件变动时，覆盖原hash文件
    def write_hash_db(self, type_):
        time_string = time.time()
        try:
            if type_ == "Initialization":
                if not os.path.exists(self.HASH_DB):
                    f = open(self.HASH_DB, "w")
                    f.close()
                if os.path.getsize(self.HASH_DB) == 0:
                    f = open(self.HASH_DB, 'w')
                    for check_dir in self.CHECK_DIR:
                        for full_path, file_hash in self.get_dir_hash(check_dir).items():
                            f.write(full_path + "||" + file_hash + "||" + str(time_string) + "\n")
                    f.close()
            elif type_ == "Coverage":
                if os.path.exists(self.HASH_DB):
                    os.remove(self.HASH_DB)
                f = open(self.HASH_DB, 'w')
                for check_dir in self.CHECK_DIR:
                    for full_path, file_hash in self.get_dir_hash(check_dir).items():
                        f.write(full_path + "||" + file_hash + "||" + str(time_string) + "\n")
                f.close()
        except IOError as e:
            app_logger.error("write hash db failed: " + str(e))

    # 检测操作类型，判断出现文件变动时，是修改还是创建
    # True为修改
    # Flase为创建
    @staticmethod
    def check_operation_type(file_path, history_file_path_list):
        return True if file_path in history_file_path_list else False

    # 检测是否存在prelink服务
    # 返回服务真假，和日志内容
    def check_prelink_service(self):
        for path in self.PRELINK_LOG_PATH:
            if os.path.exists(path):
                file_object = open(path)
                try:
                    all_the_text = file_object.read()
                finally:
                    file_object.close()
                return True, all_the_text
        return False, ""

    def check_dir_hash(self):
        # 判断是否出现文件变动
        hash_file_type = False
        # 最新hash文件列表
        # current_hash_list_content = []
        # 获取HASH库文件列表
        history_hash_list_content, history_file_path_list = self.get_history_hash_list()
        if (not history_hash_list_content) or (not history_file_path_list):
            return

        # 判断是否存在prelink服务，并返回内容
        prelink_service_exists, prelingk_log = self.check_prelink_service()

        # 开始针对监控目录进行检测
        for check_dir in self.CHECK_DIR:
            current_hash_list_content = self.get_dir_hash(check_dir)
            for full_path in current_hash_list_content:
                # 判断是否存在hash记录
                if full_path not in history_hash_list_content:
                    hash_file_type = True
                    # 判断是否是prelink服务更新
                    if prelink_service_exists and prelingk_log and prelingk_log.find(full_path) > 0:
                        # 判断是否存在prelink此条日志
                        continue
                    # 记录变动文件结果
                    self.file_malware.append(
                        {'file': full_path,
                         'action': 'Edit' if self.check_operation_type(
                             full_path,
                             history_file_path_list
                         ) else 'Create',
                         'newMD5': current_hash_list_content[full_path]
                         }
                    )

        # 存在文件修改，hash进行覆盖
        if hash_file_type:
            self.write_hash_db("Coverage")


if __name__ == '__main__':
    info = FileCheck().file_malware
    for i in info:
        print(i)
