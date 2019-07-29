# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.plugins.HostInfo import *
from lib.plugins.FileAnalysis import *
from lib.plugins.HistoryAnalysis import *
from lib.plugins.ProcAnalysis import *
from lib.plugins.NetworkAnalysis import *
from lib.plugins.BackdoorAnalysis import *
from lib.plugins.UserAnalysis import *
from lib.plugins.ConfigAnalysis import *
from lib.plugins.LogAnalysis import *
from lib.plugins.RootkitAnalysis import *
from lib.plugins.WebshellAnalysis import *
from lib.plugins.SysInit import *
from lib.plugins.SearchFile import *
from lib.core.dataaggregation import *


def main(path):
    parser = optparse.OptionParser()
    parser.add_option("--version", dest="version", default=False, action='store_true', help="current version")

    group = optparse.OptionGroup(parser, "Mode", "GScan running mode options")
    group.add_option("--overseas", dest="overseas", default=False, action='store_true',
                     help="Overseas Mode, do not match overseas IP")
    group.add_option("--full", dest="full_scan", default=False, action='store_true',
                     help="Full Scan Mode")
    group.add_option("--debug", dest="debug", default=False, action='store_true',
                     help="Debug Mode, more verbose information output")
    group.add_option("--dif", dest="diffect", default=False, action='store_true',
                     help="Differential-scan Mode, compare with last scan results")
    group.add_option("--sug", dest="suggestion", default=False, action='store_true',
                     help="Manual troubleshooting suggestions")
    group.add_option("--pro", dest="programme", default=False, action='store_true',
                     help="Output solution")

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Optimization", "Optimization options")
    group.add_option("--time", dest="time", type='string',
                     help="Search for changed files within a specified time, "
                          "demo: --time='2019-05-07 00:00:00~2019-05-07 23:00:00'")
    group.add_option("--job", dest="job", default=False, action='store_true',
                     help="Add to crontab (default, run once a day at 0:00)")
    group.add_option("--hour", dest="hour", type='string', help="run once every N hour(s)")
    group.add_option("--log", dest="logdir", default=False, action='store_true',
                     help="Back up all security logs of the current system (Not supported yet)")
    parser.add_option_group(group)

    options, _ = parser.parse_args()

    # 初始化全局模块
    init()
    # 设置调试模式
    set_value('DEBUG', True if options.debug else False)
    # 设置国内ip模式
    set_value('Overseas', True if options.overseas else False)
    # 设置手工排查建议
    set_value('suggestion', True if options.suggestion else False)
    # 设置风险处理方案
    set_value('programme', True if options.programme else False)
    # 设置扫描模式为差异扫描
    set_value('diffect', True if options.diffect else False)
    # 设置扫描模式为完全扫描
    set_value('SCAN_TYPE', 2 if options.full_scan else 1)

    # 系统执行目录
    set_value('SYS_PATH', path)
    # 扫描日志目录
    set_value('LOG_PATH', path + "/log/gscan.log")
    # 结果记录目录
    set_value('DB_PATH', path + "/db/db.txt")
    # 扫描结果
    set_value('RESULT_INFO', [])

    if options.logdir:
        print('\033[1;32mStart backing up the system security log...\033[0m\n')
        print('\033[1;32mNot supported yet\033[0m\n')
    elif options.job:
        print('\033[1;32mAdd a timed task, we recommend that you perform a scan before adding.\033[0m\n')
        if cron_write('0' if not options.hour else options.hour):
            print('Timing task added, via "crontab -l" check it.')
        else:
            print('\033[1;31mAdding failed, it is recommended to add it manually. via "crontab -e"\033[0m\n')
    elif options.time:
        print('\033[1;32mStart file search...\033[0m\n')
        SearchFile(options.time).run()
    elif options.version:
        return
    else:
        # 创建日志文件
        mkfile()
        file_write('Start system security scanning...\n')
        print('\033[1;32mStart system security scanning...\033[0m')
        # 获取恶意特征信息
        get_malware_info(path)
        # 主机信息获取
        HostInfo().run()
        # 系统初始化检查
        SysInit().run()
        # 文件类安全检测
        FileAnalysis().run()
        # 主机历史操作类扫描
        HistoryAnalysis().run()
        # 主机进程类安全扫描
        ProcAnalysis().run()
        # 网络链接类安全扫描
        NetworkAnalysis().run()
        # 后门类扫描
        BackdoorAnalysis().run()
        # 账户类扫描
        UserAnalysis().run()
        # 安全日志类
        LogAnalysis().run()
        # 安全配置类
        ConfigAnalysis().run()
        # rootkit检测
        RootkitAnalysis().run()
        # WEBShell类扫描
        WebshellAnalysis().run()
        # 漏洞扫描

        # 路径追溯
        DataAggregation().run()

        # 输出报告
        print('-' * 30)
        print('\033[1;32mScan completed. The result has been saved to the file(%s).\033[0m' % get_value('LOG_PATH'))
