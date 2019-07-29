# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

from lib.core.common import *
from lib.plugins.Webserver import *
# from lib.core.globalvar import *
import platform


# 作者：咚咚呛
# 分析主机上webshell类文件
# 1、提取nginx的web目录，进行安全扫描
# 2、提取tomcat的web目录，进行安全扫描
# 3、提取jetty的web目录，进行安全扫描
# 4、提取apache的web目录，进行安全扫描
# 5、提取resin的web目录，进行安全扫描
# 6、提取jboss的web目录，进行安全扫描
# 7、提取weblogic的web目录，进行安全扫描
# 8、提取lighttpd的web目录，进行安全扫描


class WebshellAnalysis:
    def __init__(self):
        self.name = 'Webshell'
        self.yaralib = None
        try:
            import yara as yaralib
            self.yaralib = yaralib
        except ImportError:
            pass

        # WEB目录
        self.webroot_list = []
        # yara的webshell规则
        self.rule = os.path.dirname(os.path.abspath(__file__)) + '/webshell_rule/'
        # 恶意webshell列表
        self.webshell_list = []

    def getWebRoot(self):
        webroot_ = Webserver()
        webroot_.run()
        self.webroot_list = webroot_.webroot

    # 将yara规则编译
    def getRules(self):
        index = 0
        filepath = {}
        for dirpath, dirs, files in os.walk(self.rule):
            for file in files:
                ypath = os.path.join(dirpath, file)
                key = "rule" + str(index)
                filepath[key] = ypath
                index += 1
        try:
            yararule = self.yaralib.compile(filepaths=filepath)
            return yararule
        except Exception as e:
            app_logger.error("yara file compile failed: " + str(e))
            return None

    def scan_web(self, yararule):
        for webroot_ in self.webroot_list:
            if not os.path.exists(webroot_):
                continue
            for file in gci(webroot_):
                try:
                    if not os.path.exists(file) or os.path.isdir(file):
                        continue
                    if (os.path.getsize(file) == 0) or (os.path.getsize(file) > 1048576*10):
                        continue
                        # round(os.path.getsize(file) / float(1024 * 1024)) > 10): continue
                    if yararule is None:
                        continue
                    fp = open(file, 'rb')
                    matches = yararule.match(data=fp.read())
                    if len(matches):
                        self.webshell_list.append(file)
                        malice_result(self.name, 'webshell', file, '',
                                      'matched webshell characteristics, rules: %s' % matches[0],
                                      '[1]cat %s' % file, 'Risk',
                                      programme='rm %s #delete webshell file' % file)
                except Exception as e:
                    app_logger.error(str(e))
                    continue

    def init_scan(self):
        try:
            if self.yaralib is None:
                sys_path = get_value('SYS_PATH')
                dependent_libraries_2_6 = "/lib/egg/yara_python-3.5.0-py2.6-linux-2.32-x86_64.egg"
                dependent_libraries_3_10 = "/lib/egg/yara_python-3.5.0-py2.7-linux-3.10-x86_64.egg"
                dependent_libraries_4_20 = "/lib/egg/yara_python-3.8.1-py2.7-linux-4.20-x86_64.egg"
                dependent_libraries_16 = "/lib/egg/yara_python-3.5.0-py2.7-macosx-10.12-x86_64.egg"
                dependent_libraries_17 = "/lib/egg/yara_python-3.5.0-py2.7-macosx-10.13-x86_64.egg"
                _kernel = platform.release()
                if _kernel.startswith('2.6'):
                    sys.path.append(sys_path + dependent_libraries_2_6)
                # elif _kernel.startswith('3.') and ("6." in str(platform.dist())):
                elif _kernel.startswith('3.') and (sys.version_info < (2, 7)):
                    sys.path.append(sys_path + dependent_libraries_2_6)
                elif _kernel.startswith('3.'):
                    sys.path.append(sys_path + dependent_libraries_3_10)
                elif _kernel.startswith('4.'):
                    sys.path.append(sys_path + dependent_libraries_4_20)
                elif _kernel.startswith('16.'):
                    sys.path.append(sys_path + dependent_libraries_16)
                elif _kernel.startswith('17.'):
                    sys.path.append(sys_path + dependent_libraries_17)
                else:
                    app_logger.error("webshell scan init failed: not found yara dependent_libraries.")
                    return False

                import yara as yaralib
                self.yaralib = yaralib

        except Exception as e:
            app_logger.error("webshell scan init failed: " + str(e))
            return False
        else:
            return True

    def run(self):
        print('\nWebshell scan...')
        file_write('\nWebshell scan...\n')

        string_output(' [1]Webshell')
        suspicious, malice, skip = False, False, False
        self.getWebRoot()
        if not self.init_scan():
            skip = True
            result_output_tag(suspicious, malice, skip)
        # compile yar
        yararule = self.getRules()
        self.scan_web(yararule)

        if len(self.webshell_list) > 0:
            malice = True
        result_output_tag(suspicious, malice, skip)
        result_output_file(self.name)


if __name__ == '__main__':
    info = WebshellAnalysis()
    info.run()
    print("Webshell Suspicious File: ")
    for info in info.webshell_list:
        print(info)
