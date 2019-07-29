# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

import json
import logging
import os
import pwd
import re
import sys
import time
from imp import reload

from lib.core.globalvar import *
# from lib.core.ip.ip import *
from lib.core import ipdb

# 作者：咚咚呛
# 功能：调用的公共库
# 版本：v0.1

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf-8')

# 用于url提取境外IP信息
IP_HTTP_MATCHER = re.compile(r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                             r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
LAN_IP_MATCHER = re.compile(
    r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}'
    r'\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})')
IP_MATHER = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
# ipdb
IPIP = ipdb.City("./lib/core/ipdb/ipipfree.ipdb")
# 恶意特征列表list
malware_infos = []


logging.addLevelName(logging.CRITICAL, "\033[1;41m%s\033[1;0m" % (
    logging.getLevelName(logging.CRITICAL)))
logging.addLevelName(logging.ERROR, "\033[1;31m%s\033[1;0m" % (
    logging.getLevelName(logging.ERROR)))
logging.addLevelName(logging.WARNING, "\033[0;33m%s\033[0m" % (
    logging.getLevelName(logging.WARNING)))
logging.addLevelName(logging.INFO, "\033[0;32m%s\033[0m" % (
    logging.getLevelName(logging.INFO)))
app_logger = logging.getLogger("GScanPlus")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    "%(levelname)s:%(filename)s:L%(lineno)s:%(message)s"))
app_logger.addHandler(handler)
app_logger.setLevel(logging.DEBUG)


# 颜色打印前端，根据特征赋予字符不同的颜色
# 用于用户端视觉效果的打印。
def pringf(strings, security=False, suspicious=False, malice=False):
    if security:
        # 安全显示绿色
        print(('\033[1;32m%s \033[0m' % strings) + ' ]')
    elif suspicious:
        # 可疑显示黄色
        print(('\033[1;33m%s \033[0m' % strings) + ' ]')
    elif malice:
        # 恶意显示红色
        print(('\033[1;31m%s \033[0m' % strings) + ' ]')
    else:
        print('%s' % strings)
    sys.stdout.flush()
    file_write(('%s ' % strings) + ' ]\n')


# 获取字符串宽度，包含汉语、字符、数字等
# 返回：字符串长度大小
def get_str_width(string):
    widths = [
        (126, 1), (159, 0), (687, 1), (710, 0), (711, 1),
        (727, 0), (733, 1), (879, 0), (1154, 1), (1161, 0),
        (4347, 1), (4447, 2), (7467, 1), (7521, 0), (8369, 1),
        (8426, 0), (9000, 1), (9002, 2), (11021, 1), (12350, 2),
        (12351, 1), (12438, 2), (12442, 0), (19893, 2), (19967, 1),
        (55203, 2), (63743, 1), (64106, 2), (65039, 1), (65059, 0),
        (65131, 2), (65279, 1), (65376, 2), (65500, 1), (65510, 2),
        (120831, 1), (262141, 2), (1114109, 1),
    ]
    width = 0
    for each in string:
        if ord(each) == 0xe or ord(each) == 0xf:
            # each_width = 0
            continue
        elif ord(each) <= 1114109:
            for num, wid in widths:
                if ord(each) <= num:
                    each_width = wid
                    width += each_width
                    break
            continue

        else:
            each_width = 1
        width += each_width

    return width


# 对齐字符串，用于用户视觉上的打印
# 返回：对其后字符串
def align(string, width=40):
    string_width = get_str_width(string)
    if width > string_width:
        return string + ' ' * (width - string_width)
    else:
        return string


# 检测打印信息输出
def string_output(string):
    print(align(string, 40) + '[ ', end='')
    file_write(align(string, 30) + '[ ')


# 获取文件的最近的改动时间
# 返回:文件更改时间戳
def get_file_attribute(file):
    try:
        # 文件最近修改时间
        ctime = os.stat(file).st_mtime
        cctime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctime))
        # 文件所属者uid
        uid = os.stat(file).st_uid
        username = pwd.getpwuid(uid).pw_name
        return cctime, username
    except Exception as e:
        app_logger.error(str(e))
        return "", ""


# 获取进程的开始时间
# 返回：进程开始时间
def get_process_start_time(pid):
    user, stime = '', ''
    try:
        pro_info = os.popen(
            "ps -eo pid,user,lstart 2>/dev/null|grep -v 'grep'|awk '{if($1==%s) "
            "{printf $1\";;\"$2\";;\";for(i=3;i<NF;i++) printf($i\" \"); print(\"\\n\")}}'" % str(
                pid)).readlines()
        for infos in pro_info:
            info = infos.strip()
            if pid == info.split(' ')[0].strip():
                user = info.split(' ', 2)[1].strip()
                sstime = info.split(' ', 2)[2].strip()
                stime = os.popen("date -d " + sstime + " '+%Y-%m-%d %H:%M:%S' 2>/dev/null").readlines()
                return user, stime[0].strip()
        return user, stime
    except Exception as e:
        app_logger.error(str(e))
        return user, stime


# 检测风险结果，进行全局变量结果录入
# 每个风险详情包含几项
# 1、风险检测大项 checkname
# 2、风险名称 vulname
# 3、异常文件 file
# 4、异常进程 pid
# 4、所属用户 user
# 4、异常信息 info
# 6、异常时间 mtime
# 7、风险等级 level 存在风险-可疑
# 7、建议手工确认步骤 consult
# 返回：检测项恶意信息数组
def malice_result(checkname, vulname, file, pid, info, consult, level, mtime='', user='', programme=''):
    mtime_temp, user_temp = '', ''
    if file and os.path.exists(file):
        mtime_temp, user_temp = get_file_attribute(file)
    if pid:
        mtime_temp, user_temp = get_process_start_time(pid)
    if not mtime:
        mtime = mtime_temp
    if not user:
        user = user_temp
    malice_info = {'CheckName': checkname, 'RiskName': vulname, 'AbnormalFile': file, 'PID': pid,
                   'AbnormalTime': mtime, 'User': user,
                   'Info': ' '.join(info.split()), 'ManualCheck': consult, 'RiskLevel': level,
                   'Solution': programme}
    result_info = get_value('RESULT_INFO')
    result_info.append(malice_info)
    set_value('RESULT_INFO', result_info)


def unique_result_info(result_info):
    """
    Remove duplicate elements from the object.
    :param result_info:
    :return: [{}]
    """
    new_li = []
    for i in result_info:
        if i not in new_li:
            new_li.append(i)
    return new_li


# 结果内容输出到文件
def result_output_file(tag):
    debug = get_value('DEBUG')
    result_info = get_value('RESULT_INFO')
    info = []
    for result in result_info:
        if result['CheckName'] == tag:
            info.append(result)
    if len(info) > 0:
        new = unique_result_info(info)
        file_write('-' * 30 + '\n')
        file_write(tag + '\n')
        if debug:
            print(tag)
        for info in new:
            file_write(json.dumps(info, ensure_ascii=False) + '\n')
            if debug:
                print(json.dumps(info, ensure_ascii=False))
    if debug:
        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))


# 分析结果输出，用于用户视觉效果
def result_output_tag(suspicious=False, malice=False, skip=False):
    if malice:
        pringf('RiskExist', malice=True)
    elif suspicious:
        pringf('Warning', suspicious=True)
    elif skip:
        pringf('Skipped', suspicious=True)
    else:
        pringf('OK', security=True)


# 递归目录返回文件名列表
def gci(filepath):
    filename = []
    try:
        files = os.listdir(filepath)
        for fi in files:
            fi_d = os.path.join(filepath, fi)
            if os.path.isdir(fi_d):
                filename = filename + gci(fi_d)
            else:
                filename.append(os.path.join(filepath, fi_d))
        return filename
    except Exception as e:
        app_logger.error(str(e))
        return filename


# 创建日志文件
def mkfile():
    sys_path = get_value('SYS_PATH')
    log_path = get_value('LOG_PATH')
    db_path = get_value('DB_PATH')
    # 判断日志目录是否存在，不存在则创建日志目录
    if not os.path.exists(sys_path + '/log/'):
        os.mkdir(sys_path + '/log/')
    if not os.path.exists(sys_path + '/db/'):
        os.mkdir(sys_path + '/db/')
    # 判断日志文件是否存在，不存在则创建,存在则情况
    f = open(log_path, "w")
    f.truncate()
    f.close()
    # 判断本地数据文件是否存在，不存在则创建
    if not os.path.exists(db_path):
        f = open(db_path, "w")
        f.truncate()
        f.close()


def file_write(content):
    log_path = get_value('LOG_PATH')
    f = open(log_path, 'a+')
    f.write(content)
    f.close()


# 分析字符串是否包含反弹shell或者恶意下载执行的特征
def check_shell(content):
    try:
        # reverse-shell
        if ((('bash ' in content) or ('exec ' in content) or ('ksh ' in content) or ('zsh ' in content)) and (
                ('/dev/tcp/' in content) or
                ('telnet ' in content) or
                ('nc ' in content) or
                (('exec ' in content) and ('socket' in content)) or
                ('curl ' in content) or
                ('wget ' in content) or
                ('lynx ' in content)
        )) or (".decode('base64')" in content):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content
        # malware-download
        elif (('wget ' in content) or ('curl ' in content)) and \
                ((' -o ' in content) or (' -O ' in content) or (' -s ' in content)) and \
                ((' http' in content) or (' ftp' in content)) and \
                (('php ' in content) or ('perl ' in content) or ('python ' in content) or ('sh ' in content) or
                 ('ksh ' in content) or ('zsh ' in content) or ('bash ' in content)):
            return content
        return False
    except Exception as e:
        app_logger.error(str(e))
        return False


# 获取配置文件的恶意域名等信息
def get_malware_info(path):
    try:
        malware_path = path + '/lib/malware/'
        if not os.path.exists(malware_path):
            return
        for file in os.listdir(malware_path):
            for line in open(malware_path + file):
                malware = line.strip()
                if len(malware) > 5:
                    if malware[0] != '#' and malware[0] != '.' and ('.' in malware):
                        malware_infos.append(malware)
    except Exception as e:
        app_logger.error(str(e))
        return


# 分析字符串是否包含境外IP
# 存在境外IP匹配返回真
# 不存在境外ip返回假
def check_contents_ip(contents):
    """
    return list of overseas ip, or [] (not found)
    :param contents:
    :return:
    """
    overseas_ip_list = list()
    try:
        overseas = get_value('Overseas')
        if overseas:
            return overseas_ip_list
        for item in IP_HTTP_MATCHER.finditer(contents):
            ip_http = item.group()
            for ip_group in IP_MATHER.finditer(ip_http):
                ip = ip_group.group()
                if not LAN_IP_MATCHER.fullmatch(ip):
                    if sys.version_info < (3, 0):
                        country = IPIP.find_info(ip.decode(), "CN").country_name
                    else:
                        country = IPIP.find_info(ip, "CN").country_name
                    if not (country == "本地链路" or country == "保留地址" or country == "共享地址" or
                            country == "本机地址" or country == "局域网" or country == "中国" or
                            country == "114DNS.COM"):
                        overseas_ip_list.append(ip)

        return overseas_ip_list
    except Exception as e:
        app_logger.error(str(e))
        return overseas_ip_list


# 判断是否为ip
# 是ip 返回真
# 非ip 返回假
def isIP(str_ip):
    if IP_MATHER.match(str_ip):
        return True
    else:
        return False


# 检测IP是否境外IP
# 是境外ip则返回真
# 否则返回假
def check_ip(ip):
    try:
        overseas = get_value('Overseas')
        if overseas:
            return False
        ip = ip.strip()
        if not isIP(ip):
            return False
        if LAN_IP_MATCHER.match(ip):
            return False
        if sys.version_info < (3, 0):
            country = IPIP.find_info(ip.decode(), "CN").country_name
        else:
            country = IPIP.find_info(ip, "CN").country_name
        if country == "本地链路" or country == "保留地址" or country == "共享地址" or \
                country == "本机地址" or country == "局域网" or country == "中国" or \
                country == "114DNS.COM":
            return False
        else:
            return True
    except Exception as e:
        app_logger.error(str(e))
        return False


# 分析一串字符串是否包含反弹shell、获取对应字串内可能存在的文件，并判断文件是否存在恶意特征。
# 匹配成功则返回恶意特征信息
# 否则返回空
def analysis_strings(contents):
    if "GScan" in contents or "gscan" in contents:
        return ""
    try:
        content = contents.replace('\n', '')
        # 反弹shell类
        if check_shell(content):
            return "Reverse-Shell: %s" % content
        # 境外IP操作类
        overseas_ip_list = check_contents_ip(content)
        if overseas_ip_list:
            # logging.error("Overseas IP operation: %s" % ";".join(overseas_ip_list))
            return "Overseas IP operation: %s" % ";".join(overseas_ip_list)
        else:
            for file in content.split(' '):
                if not os.path.exists(file):
                    continue
                if os.path.isdir(file):
                    continue
                malware = analysis_file(file)
                if malware:
                    return "Include malicious files: %s, Suspicious content: %s" % (file, malware)
        return ""
    except Exception as e:
        app_logger.error(str(e))
        return ""


# 分析文件是否包含恶意特征、反弹shell特征、境外ip类信息
# 存在返回恶意特征
# 不存在返回空
def analysis_file(file, mode='fast'):
    try:
        scan_type = get_value('SCAN_TYPE')
        debug = get_value('DEBUG')
        overseas = get_value('Overseas')

        if not os.path.exists(file) or os.path.isdir(file):
            return None
        # if (" " in file) or ("GScan" in file) or ("\\" in file) or (".jpg" in file) or (")" in file) or (
        #         "(" in file) or (".log" in file): return ""
        if get_value("SYS_PATH") in file:
            return None
        # skip file size>10M or size=0
        if (os.path.getsize(file) == 0) or (os.path.getsize(file) > 1048576 * 10):
            return None
        strings = os.popen("strings '%s' 2>/dev/null" % file).readlines()
        if len(strings) > 200:
            return None

        # time.sleep(0.01)
        for strs in strings:
            strs = strs.strip()
            if check_shell(strs):
                if debug:
                    print('File: %s ，bash shell :%s' % file, strs)
                return "Reverse-Shell: %s" % strs
            # 完全扫描会带入恶意特征扫描
            if scan_type == 2:
                time.sleep(0.01)
                for malware in malware_infos:
                    if malware.replace('\n', '') in strs:
                        if debug:
                            print('File: %s, Malicious feature: %s' % file, malware)
                        return "Malicious feature: %s, Matching rules: %s" % (strs, malware)
            if overseas:
                continue
            overseas_ip_list = check_contents_ip(strs)
            if overseas_ip_list:
                if debug:
                    print('File: %s, Overseas IP operation: %s' % file, ";".join(overseas_ip_list))
                return "Overseas IP operation: %s" % strs
        return None
    except Exception as e:
        app_logger.error(str(e))
        return None


# 写定时任务信息
def cron_write(hour='0'):
    sys_path = get_value('SYS_PATH')
    if not os.path.exists('/var/spool/cron/'):
        return False
    if os.path.exists('/var/spool/cron/root'):
        f = open('/var/spool/cron/root', 'a+')
        # 每N小时执行一次
        if hour != '0':
            f.write('* */' + hour + ' * * * python ' + sys_path + '/GScan.py --dif\n')
        else:
            f.write('0 0 * * * python ' + sys_path + '/GScan.py --dif\n')
        f.close()
    else:
        f = open('/var/spool/cron/root', 'w')
        # 每N小时执行一次
        if hour != '0':
            f.write('* */' + hour + ' * * * python ' + sys_path + '/GScan.py --dif\n')
        else:
            f.write('0 0 * * * python ' + sys_path + '/GScan.py --dif\n')
        f.close()
    return True


# 日志输出到指定文件，用于syslog打印
def loging():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('GScan')
    sys_path = get_value('SYS_PATH')
    logfile = sys_path + '/log/log.log'
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.propagate = False
    return logger
