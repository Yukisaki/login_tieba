import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64
import execjs
import time
import re
from urllib.parse import quote

def log_baidu(name, passwd):
    proxies = {"http": "http://c_yuanjun-001:Yj522008@10.185.113.100:8002",
               "https": "https://c_yuanjun-001:Yj522008@10.185.113.100:8002"}

    s = requests.Session()
    s.get('http://tieba.baidu.com', proxies=proxies)

    header1 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'
    }
    header2 = {
        'Host': 'passport.baidu.com',
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'h-CN,zh;q=0.8,en;q=0.6'
    }

    js = '''
    function callback() {
                return 'bd__cbs__' + Math.floor(2147483648 * Math.random()).toString(36)
            }
    function gid(){
            return 'xxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (e) {
            var t = 16 * Math.random() | 0,
            n = 'x' == e ? t : 3 & t | 8;
            return n.toString(16)
            }).toUpperCase()

        }
    '''
    ejs = execjs.compile(js)
    # 获取gid
    gid = ejs.call('gid')
    # 获取callback
    callback1 = ejs.call('callback')
    #获取token
    log_url = 'https://passport.baidu.com/v2/api/?login'
    tokenUrl = "https://passport.baidu.com/v2/api/?getapi&tpl=netdisk&subpro=netdisk_web&apiver=v3" \
               "&tt=%d&class=login&gid=%s&logintype=basicLogin&callback=%s" % (time.time() * 1000, gid, callback1)


    h = s.get(tokenUrl , proxies=proxies)
    # h = s.get('https://passport.baidu.com/v2/api/?getapi&tpl=tb&apiver=v3', proxies=proxies, headers=header1)
    h.encoding = 'utf8'
    h = h.text
    pattern = re.compile('\"token\" \: \"(.*?)\"')
    t = re.findall(pattern, h)
    token = t[0]
    # print(token)
    # 获取密钥和pubkey
    callback2 = ejs.call('callback')
    rsaUrl = "https://passport.baidu.com/v2/getpublickey?token=%s&" \
             "tpl=netdisk&subpro=netdisk_web&apiver=v3&tt=%d&gid=%s&callback=%s" % (
             token, time.time() * 1000, gid, callback2)
    r = s.get(rsaUrl, proxies=proxies)
    r.encoding = 'utf8'
    r = r.text
    # print(r)
    pattern = re.compile('\"key\"\:\'(.*?)\'')
    a = re.findall(pattern, r)
    key = a[0]
    # print(key)
    pattern = re.compile('\"pubkey\"\:\'(.*?)\'')
    p = re.findall(pattern, r)
    pubkey = p[0]
    # print(pubkey)
    #加密password
    password = passwd  # 填上自己的密码
    pubkey = pubkey.replace('\\n', '\n').replace('\\', '')
    # print(pubkey)
    rsakey = RSA.importKey(pubkey)
    # print(rsakey)
    cipher = PKCS1_v1_5.new(rsakey)
    password = base64.b64encode(cipher.encrypt(password))
    # print(password)

    callback3 = ejs.call('callback')

    data={
        'apiver':'v3',
        'charset':'utf-8',
        'countrycode':'',
        'crypttype':12,
        'detect':1,
        'foreignusername':'',
        'idc':'',
        'isPhone':'false',
        'logLoginType':'pc_loginDialog',
        'loginmerge':True,
        'staticpage':'https://tieba.baidu.com/tb/static-common/html/pass/v3Jump.html',
        'logintype':'dialogLogin',
        'quick_user':0,
        'safeflg':0,
        'u':'https://tieba.baidu.com/index.html',
        'tpl':'tb',
        'username':name,
        'callback':'parent.'+callback3,
        'gid':gid,
        'rsakey':key,
        'token':token,
        'password':password,
        'tt':'%d'%(time.time()*1000),
    }

    r1 = s.post('https://passport.baidu.com/v2/api/?login',data=data, proxies=proxies)
    r1.encoding = 'utf8'
    r1 = r1.text
    # print(r1)
    pattern = re.compile('codeString\=(.*?)\&')
    codeString = re.findall(pattern, r1)[0]
    data['codestring'] = codeString




    verifyFail = True
    while verifyFail:
        genimage_param = ''
        if len(genimage_param) == 0:
            genimage_param = codeString

        verifycodeUrl = "https://passport.baidu.com/cgi-bin/genimage?%s" % genimage_param
        verifycode = s.get(verifycodeUrl)
        #############下载验证码###################################
        with open('verifycode.png', 'wb') as codeWriter:
            codeWriter.write(verifycode.content)
            codeWriter.close()
        #############输入验证码###################################
        verifycode = input("Enter your input verifycode: ")
        callback4 = ejs.call('callback')
        #############检验验证码###################################
        checkVerifycodeUrl = 'https://passport.baidu.com/v2/?' \
                             'checkvcode&token=%s' \
                             '&tpl=netdisk&subpro=netdisk_web&apiver=v3&tt=%d' \
                             '&verifycode=%s&codestring=%s' \
                             '&callback=%s' % (token, time.time() * 1000, quote(verifycode), codeString, callback4)
        # print(checkVerifycodeUrl)
        state = s.get(checkVerifycodeUrl)
        # print(state.text)
        if state.text.find(u'验证码错误') != -1:
            print('验证码输入错误...已经自动更换...')
            callback5 = ejs.call('callback')
            changeVerifyCodeUrl = "https://passport.baidu.com/v2/?reggetcodestr" \
                                  "&token=%s" \
                                  "&tpl=netdisk&subpro=netdisk_web&apiver=v3" \
                                  "&tt=%d&fr=login&" \
                                  "vcodetype=de94eTRcVz1GvhJFsiK5G+ni2k2Z78PYRxUaRJLEmxdJO5ftPhviQ3/JiT9vezbFtwCyqdkNWSP29oeOvYE0SYPocOGL+iTafSv8pw" \
                                  "&callback=%s" % (token, time.time() * 1000, callback5)
            print(changeVerifyCodeUrl)
            verifyString = s.get(changeVerifyCodeUrl)
            pattern = re.compile('"verifyStr"\s*:\s*"(\w+)"')
            match = pattern.search(verifyString.text)
            if match:
                ###########获取verifyString#############################3
                verifyString = match.group(1)
                genimage_param = verifyString
                print(verifyString)

            else:
                verifyFail = False
                raise Exception

        else:
            verifyFail = False

    data['verifycode'] = verifycode





    data['ppui_logintime'] = 81755
    r2 = s.post('https://passport.baidu.com/v2/api/?login', data=data, proxies=proxies)
    r2.encoding = 'utf8'
    # print(r2.text)
    h1 = s.get('https://tieba.baidu.com/index.html', proxies=proxies)
    h1.encoding = 'utf8'
    with open('h1.txt', 'w',encoding='utf8') as f:
        f.write(h1.text)
        f.close()
if __name__ == '__main__':
    name = ''
    passwd = b''
    log_baidu(name, passwd)
