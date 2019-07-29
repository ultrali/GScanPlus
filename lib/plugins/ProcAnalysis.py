# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 分析进程信息
# 1、cpu使用超过70% 的进程
# 2、内存使用超过70% 的进程
# 3、隐藏的进程,主要针对mount --bind等挂接方式隐藏进程的检查,解决方案
# 4、是否存在反弹bash的进程
# 5、带有挖矿、黑客工具、可疑进程名的进程
# 6、当前执行的程序，判断可执行exe是否存在恶意域名特征特征

class ProcAnalysis:
    def __init__(self, cpu=70, mem=70):
        # cpu、内存使用率
        self.cpu, self.mem = cpu, mem
        # 可疑的进程列表
        self.process_backdoor = []
        self.name = 'Process Check'

    # 判断进程的可执行文件是否具备恶意特征
    def exe_analysis(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/proc/'):
                return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)):
                        continue
                    malware = analysis_file(filepath)
                    if malware:
                        lnstr = os.readlink(filepath)
                        malice_result(self.name, 'executable file process scan', lnstr, file, malware,
                                      '[1]ls -a %s [2]strings %s' % (filepath, filepath), 'Risk',
                                      programme='kill %s #Kill Malicious Processes' % lnstr)
                        malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))

    # 过滤反弹shell特征
    def shell_analysis(self):
        suspicious, malice = False, False
        try:
            process = os.popen(
                "ps -ewwo pid,command 2>/dev/null |"
                "awk '{if(NR>1) {printf $1\";;\";for(i=2;i<NF;i++) printf($i\" \"); print(\"\")}}'"
            ).readlines()
            for pro in process:
                pro_info = pro.strip().split(';;', 1)
                if check_shell(pro_info[1]):
                    malice_result(self.name, 'Reverse Shell Process', '', pro_info[0],
                                  'process info: %s' % pro_info[0],
                                  '[1]ps -efwww', 'Risk',
                                  programme='kill %s #Kill Malicious Processes' % pro_info[0])
                    malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 过滤cpu和内存使用的可疑问题
    def work_analysis(self):
        suspicious, malice = False, False
        try:
            cpu_process = os.popen(
               "ps -ewwo pid,pcpu,pmem,command 2>/dev/null |"
               "grep -Ev 'systemd|rsyslogd|mysqld|redis|apache|nginx|mongodb|docker|memcached|tomcat|jboss|java|php' |"
               "awk '{if(NR>1) {printf $1\";;\"$2\";;\"$3\";;\";for(i=4;i<NF;i++) printf($i\" \"); print(\"\")}}'"
            ).readlines()
            for pro in cpu_process:
                pro_info = pro.strip().split(';;', 3)
                # cpu使用超过标准
                if float(pro_info[1]) > self.cpu:
                    malice_result(self.name, 'CPU Overload', '', pro_info[0],
                                  'Process CPU Overload, process id(%s), command(%s)' % (
                                      pro_info[0], pro_info[3]),
                                  '[1]ps -efwww', 'Risk',
                                  programme='kill %s #Kill Malicious Processes' % pro_info[0])
                    suspicious = True
                # 内存使用超过标准
                if float(pro_info[2]) > self.mem:
                    malice_result(self.name, 'Memory Overload', '', pro_info[0],
                                  'Process Memory Overload, process id(%s), command(%s)' % (
                                      pro_info[0], pro_info[3]),
                                  '[1]ps -efwww', 'Risk',
                                  programme='kill %s #Kill Malicious Processes' % pro_info[0])
                    suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 检测隐藏进程
    def check_hide_pro(self):
        suspicious, malice = False, False
        try:
            pid_process = os.popen(
                "ps -ewwo pid 2>/dev/null |awk '{if(NR>1) print $1}'"
            ).readlines()
            pid_process_set = set()
            for pid in pid_process:
                pid_process_set.add(pid.strip())

            # 所有/proc目录的pid
            pid_pro_file = []
            if not os.path.exists('/proc/'):
                return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    pid_pro_file.append(file)
            hids_pid = list(set(pid_pro_file).difference(pid_process_set))
            if len(hids_pid) > 10:
                return suspicious, malice
            for pid in hids_pid:
                malice_result(self.name, 'Hidden Porcess', '', pid, 'Process(PID %s) hidden process info' % pid,
                              "[1] cat /proc/$$/mountinfo [2] umount /proc/%s [3]ps -ef |grep %s" % (pid, pid),
                              'Risk',
                              programme='umount /proc/%s & kill %s #Kill Hidden Porcess' % (pid, pid))
                malice = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    # 查询挖矿进程、黑客工具、可疑进程名称
    def keyi_analysis(self):
        suspicious, malice = False, False
        try:
            sus_process = os.popen(
                "ps -ewwo uid,pid,ppid,command 2>/dev/null | grep -v grep |"
                "grep -E 'miner|xmrig|minerd|r00t|sqlmap|nmap|hydra|aircrack' |"
                "awk '{if(NR>1) {printf $1\";;\"$2\";;\"$3\";;\";for(i=4;i<NF;i++) printf($i\" \"); print(\"\")}}'"
            ).readlines()
            for pro in sus_process:
                pro_info = pro.strip().split(';;', 3)
                malice_result(self.name, 'Malicious Process', '', pro_info[1], pro_info[3],
                              '[1]ps -efwww', 'Risk',
                              programme='kill %s #Close Malicious Process' % pro_info[1])
                suspicious = True
            return suspicious, malice
        except Exception as e:
            app_logger.error(str(e))
            return suspicious, malice

    def run(self):
        print('\nStart Process scan...')
        file_write('\nStart Process scan...\n')

        string_output(' [1]CPU and Memory Overload')
        suspicious, malice = self.work_analysis()
        result_output_tag(suspicious, malice)

        string_output(' [2]Hidden Process')
        suspicious, malice = self.check_hide_pro()
        result_output_tag(suspicious, malice)

        string_output(' [3]Reverse-Shell')
        suspicious, malice = self.shell_analysis()
        result_output_tag(suspicious, malice)

        string_output(' [4]Malicious Process')
        suspicious, malice = self.keyi_analysis()
        result_output_tag(suspicious, malice)

        string_output(' [5]Process Executable File')
        suspicious, malice = self.exe_analysis()
        result_output_tag(suspicious, malice)

        result_output_file(self.name)


if __name__ == '__main__':
    infos = ProcAnalysis()
    infos.run()
