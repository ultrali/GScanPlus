# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

import operator
import hashlib
from lib.core.common import *


# 作者：咚咚呛
# 功能：根据已知的异常风险，进行信息聚合，根据时间线排序，获取黑客的行动轨迹

class DataAggregation:
    def __init__(self):
        # 可能存在的黑客入口点信息
        self.begins = []
        # 检测结果信息
        self.result_infos = []
        # 本次新增异常风险,与历史进行数据对比
        self.dif_result_infos = []
        # 是否差异扫描
        self.diffect = False

    # 读取db文件，提取hash内容，进行结果判断存在哪些新增风险。
    def result_db_filter(self):
        old_db = []
        db_path = get_value('DB_PATH')
        for line in open(db_path):
            old_db.append(line.strip())
        for info in self.result_infos:
            hash_txt = info['CheckName'] + info['RiskName'] + info['AbnormalFile'] + info['PID'] + \
                       info['AbnormalTime'] + info['Info']
            md5obj = hashlib.md5()
            md5obj.update(hash_txt.encode("utf8"))
            hashinfo = md5obj.hexdigest()
            if hashinfo not in old_db:
                self.dif_result_infos.append(info)
        # 写检测结果到db文件
        self.write_result_to_db()

    # 写检测结果到db文件
    def write_result_to_db(self):
        db_path = get_value('DB_PATH')
        # 写结果文件到db
        f = open(db_path, 'w')
        for info in self.result_infos:
            hash_txt = info['CheckName'] + info['RiskName'] + info['AbnormalFile'] + info['PID'] + \
                       info['AbnormalTime'] + info['Info']
            md5obj = hashlib.md5()
            md5obj.update(hash_txt.encode("utf8"))
            hashinfo = md5obj.hexdigest()
            f.write(hashinfo + '\n')

    # 黑客攻击可能存在的入口点
    def attack_begins(self):
        try:
            cmd = "netstat -ntpl 2>/dev/null | grep -Ev '127.0.0.1|localhost|::1' |awk '{if (NR>2){print $4\" \"$7}}'"
            attack_begins = os.popen(cmd).readlines()
            for infors in attack_begins:
                infors = infors.strip()
                if '/' not in infors or ':' not in infors:
                    continue
                ip_port = infors.split(' ')[0]   # 0.0.0.0:22
                pid_name = infors.split(' ')[1]  # 6912/sshd
                self.begins.append({'ip_port': ip_port, 'pid_name': pid_name})
        except Exception as e:
            app_logger.error(str(e))
            return

    # 追溯溯源信息
    def agregation(self):
        suggestion = get_value('suggestion')
        programme = get_value('programme')

        if len(self.result_infos) > 0:
            say_info, i = '-' * 30 + '\n', 1
            # say_info += '根据系统分析的情况，溯源后的攻击行动轨迹为：\n' if not self.diffect else '根据系统差异分析的情况，溯源后的攻击行动轨迹为：\n'
            say_info += 'Intrusion traces found:\n' if not self.diffect \
                else 'Intrusion traces found by differential-scan:\n'
            # 入口点信息
            for begin_info in self.begins:
                # say_info += '[起点信息] 进程服务%s 端口%s 对外部公开，可能会被作为入侵起点，属于排查参考方向\n' % (
                say_info += '[Entry] service(%s) port(%s) allow public access.\n' % (
                    begin_info['pid_name'], begin_info['ip_port'])

            programme_info = '\nPreliminary solution:\n'
            # 根据时间排序
            self.result_infos.sort(key=operator.itemgetter('AbnormalTime'))
            for result_info in self.result_infos:
                if result_info['CheckName'] == 'Normal Backdoor Check':
                    say_info += "[%d][%s] Found backdoor(%s), create at(%s): %s\n" % (
                        i, result_info['RiskLevel'], result_info['RiskName'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide：%s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Configuration Risk':
                    say_info += "[%d][%s] at time(%s), RiskName(%s): %s\n" % (
                        i,
                        result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['RiskName'],
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'File Security':
                    say_info += "[%d][%s] at time(%s), Found a malicious file(%s): %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['AbnormalFile'],
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide：%s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Host Operation History':
                    say_info += "[%d][%s] at time(%s), Found a malicious operation: %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Log Audit':
                    say_info += "[%d][%s] at time(%s), Suspicious login by user(%s): %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['User'], result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Network Security':
                    say_info += "[%d][%s] at time(%s), Suspicious Network Connection: %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Process Check':
                    say_info += "[%d][%s] at time(%s), Malicious process(%s): %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['PID'], result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Rootkit':
                    say_info += "[%d][%s] at time(%s), Found a Rootkit: %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'System Initialization':
                    say_info += "[%d][%s] at time(%s), suspicious command alias: %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Account Security':
                    say_info += "[%d][%s] at time(%s), the account settings is changed: %s\n" % (
                        i, result_info['RiskLevel'], result_info['AbnormalTime']
                        if result_info['AbnormalTime'] else 'Unknown',
                        result_info['Info'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                if result_info['CheckName'] == 'Webshell':
                    say_info += "[%d][%s] at time(%s), Found a webshell: %s\n" % (
                        i, result_info['RiskLevel'],
                        result_info['AbnormalTime'] if result_info['AbnormalTime'] else 'Unknown',
                        result_info['AbnormalFile'])
                    if suggestion:
                        say_info += "           Check Guide: %s\n" % result_info['ManualCheck']
                    if programme and result_info['Solution']:
                        programme_info += "[%d] %s\n" % (i, result_info['Solution'])
                i += 1
            if programme:
                say_info += programme_info

            file_write(say_info)
            print(
                say_info.replace('[Risk]', '[\033[1;31mRisk\033[0m]').replace(
                    '[Suspicious]', '[\033[1;33mSuspicious\033[0m]').replace(
                    '[Entry]', '[\033[1;32mEntry\033[0m]')
            )
        else:
            say_info = '-' * 30 + '\n'
            say_info += 'No abnormalities were found in this scan.\n' if not self.diffect \
                else 'No abnormalities were found in this differential-scan.\n'
            print(say_info)
            file_write(say_info)

    def run(self):
        self.diffect = get_value('diffect')
        self.result_infos = get_value('RESULT_INFO')
        self.result_infos = unique_result_info(self.result_infos)
        self.result_db_filter()
        self.attack_begins()
        if self.diffect:
            self.result_infos = self.dif_result_infos
        self.agregation()

        logger = loging()
        for info in self.result_infos:
            logger.info(json.dumps(info, ensure_ascii=False))
