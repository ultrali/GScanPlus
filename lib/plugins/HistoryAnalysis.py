# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 分析用户历史操作记录
# 1、获取所有用户目录下.bash_history文件
# 2、匹配境外ip类操作

class HistoryAnalysis:
    def __init__(self):
        # 恶意操作
        self.history = []
        self.name = 'Host Operation History'

    # 获取所有用户下的操作记录，是否存在恶意ip
    def get_all_history(self):
        suspicious, malice = False, False
        # 待检测的目录和文件
        file_path = ['/home/', '/root/.bash_history', '/Users/']
        for path in file_path:
            if not os.path.exists(path):
                continue
            # 目录类，获取目录下的.bash_history文件
            if os.path.isdir(path):
                for d in os.listdir(path):
                    file = '%s%s%s' % (path, d, '/.bash_history')
                    if not os.path.exists(file):
                        continue
                    for line in open(file):
                        contents = analysis_strings(line)
                        if not contents:
                            continue
                        malice_result(self.name, 'history file scan', file, '', contents, '[1]cat %s' % file,
                                      'Risk')
                        malice = True
            # 文件类，进行文件的操作分析
            else:
                for line in open(path):
                    contents = analysis_strings(line)
                    if not contents:
                        continue
                    malice_result(self.name, 'history file scan', path, '', contents,
                                  '[1]cat %s' % path, 'Risk')
                    malice = True
        return suspicious, malice

    def run(self):
        print('\nHost Operation History scan...')
        file_write('\nHost Operation History scan...\n')

        string_output(' [1]suspicious history operations')
        suspicious, malice = self.get_all_history()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    info = HistoryAnalysis()
    info.run()
