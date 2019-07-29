# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *


# 作者：咚咚呛
# 搜索指定时间内主机改动过的所有文件

class SearchFile:
    def __init__(self, time_):
        self.time = time_.strip()

    def run(self):
        stime, etime = self.time.split('~')
        log_path = get_value('SYS_PATH') + "/log/search.log"
        debug = get_value('DEBUG')
        try:
            files = os.popen("find / -newermt '%s' ! -newermt '%s' 2>/dev/null" % (stime, etime)).readlines()
            print('Time Period: %s \nSearch Results: %d changes is found in the files or directories.' % (
                self.time, len(files)))

            if os.path.exists(log_path):
                f = open(log_path, "r+")
                f.truncate()
                f.close()
            f = open(log_path, 'a+')
            for file in files:
                file = file.strip()
                f.write(file + '\n')
                if debug:
                    print(file)
            print('Results Detail: %s' % log_path)
        except Exception as e:
            app_logger.error(str(e))


if __name__ == '__main__':
    SearchFile('2019-05-07 00:00:00~2019-05-07 12:00:00').run()
