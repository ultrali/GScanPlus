# coding:utf-8
from __future__ import print_function
from __future__ import unicode_literals

import os
import glob


# 作者：咚咚呛
# 版本：v0.1
# 功能：根据本机的web服务，提取web的根目录，供后续webshell扫描使用
# nginx
# 1、进程名称中出现-c 跟配置文件
# 2、不存在-c 获取的默认配置文件/etc/nginx/nginx.conf
# 3、去读nginx.conf
# tomcat
# 1、提取-Dcatalina.home=、-Djava.io.tmpdir=
# 2、home/webapp、home/work、tmp均纳入为web扫描目录
# jetty
# 。。。。


class Webserver:
    def __init__(self):
        self.webroot = ['/var/www/', '/tmp/']
        self.webconf = []

    @staticmethod
    def getStrPath(match, s):
        if match in s:
            path = s.split(match)[1].strip().split(' ')[0]
            return path
        return ''

    def getWebserverConf(self):
        webserver = ['nginx', 'tomcat', 'jetty', 'httpd', 'resin', 'jboss', 'weblogic', 'jenkins']
        for name in webserver:
            cmd = '''ps -ef 2>/dev/null |grep -v grep|grep %s|awk '{for(i=8;i<=NF;i++)printf $i" ";printf "\\n"}' ''' \
                  % name
            shell_process = os.popen(cmd).readlines()
            for pro in shell_process:
                if name == 'nginx':
                    conf = self.getStrPath(' -c ', pro)
                    if conf:
                        self.webconf.append({'name': 'nginx', 'conf': conf, 'home': '', 'webroot': ''})
                    else:
                        self.webconf.append(
                            {'name': 'nginx', 'conf': '/etc/nginx/nginx.conf', 'home': '', 'webroot': ''})
                elif name == 'tomcat':
                    conf = self.getStrPath(' -Dcatalina.home=', pro)
                    if conf:
                        self.webconf.append({'name': 'tomcat', 'home': conf, 'conf': '', 'webroot': conf + '/webapp'})
                        self.webconf.append({'name': 'tomcat', 'home': conf, 'conf': '', 'webroot': conf + '/work'})
                    conf = self.getStrPath(' -Djava.io.tmpdir=', pro)
                    if conf:
                        self.webconf.append({'name': 'tomcat', 'conf': '', 'webroot': conf})

                elif name == 'jetty':
                    conf = self.getStrPath(' -Djetty.home=', pro)
                    if conf:
                        self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf + '/webapp'})
                        self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf + '/work'})
                    conf = self.getStrPath(' -Djetty.webroot=', pro)
                    if conf:
                        self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf})
                    conf = self.getStrPath(' -Djava.io.tmpdir=', pro)
                    if conf:
                        self.webconf.append({'name': 'jetty', 'conf': '', 'webroot': conf})
                elif name == 'httpd':
                    conf = self.getStrPath(' -f ', pro)
                    if conf:
                        self.webconf.append({'name': 'httpd', 'conf': conf, 'home': '', 'webroot': ''})
                    else:
                        self.webconf.append(
                            {'name': 'httpd', 'conf': '/etc/httpd/conf/httpd.conf', 'home': '', 'webroot': ''})
                elif name == 'resin':
                    root_ = self.getStrPath(' --root-directory ', pro)
                    if root_:
                        self.webconf.append({'name': 'resin', 'conf': '', 'home': '', 'webroot': root_ + '/webapps'})
                    conf = self.getStrPath(' -conf ', pro)
                    if conf:
                        self.webconf.append({'name': 'resin', 'conf': conf, 'home': '', 'webroot': ''})
                elif name == 'jenkins':
                    root_ = self.getStrPath(' --webroot=', pro)
                    if root_:
                        self.webconf.append({'name': 'jenkins', 'conf': '', 'home': '', 'webroot': root_})

    # 解析nginx的配置文件，读取web路径
    def parseNginxConf(self, conf):
        if not os.path.isfile(conf):
            return

        for readline in open(conf):
            line = readline.strip()
            if line == '' or line[0] == '#':
                continue

            elif line[0:4].lower() == 'root':
                root_ = line[4:].strip().rstrip(';').strip('"').strip("'")
                self.webroot.append(root_)
            elif line.lower().startswith("include"):
                include_conf = line[len("include"):].strip().rstrip(
                    ';').strip('"').strip("'")

                if '*' in include_conf:
                    # 匹配文件通配符：? [] *
                    include_list = glob.glob(include_conf)
                    for include in include_list:
                        self.parseNginxConf(include)
                else:
                    self.parseNginxConf(include_conf)

    # 解析resin的配置文件，读取web路径
    def parseResinConf(self, conf):
        if not os.path.isfile(conf):
            return
        if not os.path.isfile(conf):
            return
        for readline in open(conf):
            line = readline.strip()
            if line == '' or line[0] == '#' or line[0:4] == '<!--':
                continue
            elif line[0:8] == '<web-app' and 'root-directory="' in line:
                root_ = line.split('root-directory="')[1].split('"')[0]
                self.webroot.append(root_)

    def getWebRoot(self):
        if len(self.webconf):
            for conf in self.webconf:
                if conf['webroot']:
                    self.webroot.append(conf['webroot'])
                else:
                    if conf['name'] == 'nginx':
                        self.parseNginxConf(conf['conf'])
                    elif conf['name'] == 'resin':
                        self.parseResinConf(conf['conf'])

    def run(self):
        # 获取配置文件
        self.getWebserverConf()
        # 获取web根目录
        self.getWebRoot()


if __name__ == '__main__':
    webroot = Webserver()
    webroot.run()
    for root in webroot.webroot:
        print(root)
