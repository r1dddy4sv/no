from curses.ascii import isdigit
from tracemalloc import start
from xmlrpc.client import Boolean, boolean
from selenium import webdriver
import openai
from selenium.webdriver.common.keys import Keys
openai.api_key='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'
import shutil
import emoji
from PIL import Image
import unlock
#import cv2
import phonie
import solveman
import base64
from capmonster_python import FuncaptchaTask
slowed=0
proxyforcaptchastr='188.165.146.197:7951:igp3021222:cDR13Rxlgl'
total_to_req_again=0
import datetime
import email
import hashlib
from io import BytesIO
from Crypto.Cipher import AES
import http.client
import os
import random
import string
import time
import urllib.parse
from random import randint

import mail as mmail
import requests
import selenium_driver_gen
from bs4 import BeautifulSoup
from random_user_agent.params import OperatingSystem, SoftwareName
from random_user_agent.user_agent import UserAgent
from requests_oauthlib import OAuth1Session
from transliterate import get_available_language_codes, translit
from twocaptcha import TwoCaptcha

http.client._MAXHEADERS = 1000
import hashlib
import json
import re
import ssl
import threading

from anticaptchaofficial.funcaptchaproxyless import funcaptchaProxyless
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
#from urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from urllib3.util.retry import Retry

# proxystr='185.130.226.44:11982'
# proxys={
#         "https" : f"https://{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
# }

                                                                            
# s=requests.Session()
# s.proxies.update(proxys)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# s.close()
# time.sleep(1)
# s=requests.Session()
# s.proxies.update(proxys)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)
# r=s.get('http://v4v6.ipv6-test.com/api/myip.php').text
# print(r)

aki=[]
CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)
tokenlocal={}

if True:
    asocks={'unlock_tw_1_0': '185.2.81.74:20414:fb5ef651-1250831:r5Xohh12', 'unlock_tw_1_1': '62.112.11.204:38883:a2b5f4d3-1193302:S1PcbFMU', 'unlock_tw_1_2': '62.112.11.204:39453:5ea729ac-1193872:J0Es6dnD', 'unlock_tw_1_3': '93.190.142.57:42564:575a7267-1234982:I97NJwp8', 'unlock_tw_1_4': '89.38.99.29:35576:254dc808-1341991:RmSUa0KY', 'unlock_tw_1_5': '185.2.81.74:29589:6ce297ee-1260006:8BFm7Nhl', 'unlock_tw_1_6': '89.38.99.29:33751:3d05be7e-1340166:UbkiV7N3', 'unlock_tw_1_7': '185.2.81.74:38577:5c740b86-1268994:9wwqXtdH', 'unlock_tw_1_8': '89.38.99.29:38258:e1d0a367-1344673:FXCZDI7y', 'unlock_tw_1_9': '185.132.177.55:25493:9835bbf4-147925:e7leGat5', 'unlock_tw_1_10': '185.132.133.232:47240:3bd24488-449690:7oAxWguX', 'unlock_tw_1_11': '89.38.99.29:17728:5cb3f8f7-1324143:D9c2SFZR', 'unlock_tw_1_12': '109.236.80.35:42267:0e192000-1310683:bUiHYdO5', 'unlock_tw_1_13': '109.236.80.35:48394:cd8e6c79-1316810:IRXI3lKH', 'unlock_tw_1_14': '190.2.146.108:26099:e80f36f6-88531:9FinavPu', 'unlock_tw_2_0': '109.236.80.35:38249:9cc453ca-1306665:hZo451Fk', 'unlock_tw_2_1': '62.112.11.204:49866:e72d6c95-1204285:8nMdAFVR', 'unlock_tw_2_2': '45.82.65.183:46172:bf695873-56361:sqeZoQuo', 'unlock_tw_2_3': '109.236.80.35:48403:1329e0cd-1316819:rffmT9Kx', 'unlock_tw_2_4': '185.2.81.74:44167:0c38c15e-1274584:QfZ2uAna', 'unlock_tw_2_5': '190.2.146.108:18202:aeb17e8a-800637:cEDzFAXT', 'unlock_tw_2_6': '185.2.81.74:17987:1d0b637a-1248404:XddnMHe6', 'unlock_tw_2_7': '109.236.80.35:14334:a63013c8-1282750:c6grXM1h', 'unlock_tw_2_8': '93.190.142.57:28089:376d849f-1220507:H7opaLdF', 'unlock_tw_2_9': '62.112.11.204:35719:35bfdf5a-1190138:Kq24xGB2', 'unlock_tw_2_10': '62.112.11.204:44814:c7f815b7-1199233:AKFmQE0b', 'unlock_tw_2_11': '45.82.65.183:36009:ec46a639-198459:pd1Oo3f2', 'unlock_tw_2_12': '62.112.11.204:35620:e02a3106-1190039:7LdTCDZV', 'unlock_tw_2_13': '93.190.142.57:42820:23de51ff-1235238:J87KaIxQ', 'unlock_tw_2_14': '185.2.81.74:15756:631c4ded-1246173:4RzKpnNE', 'unlock_tw_3_0': '89.38.99.29:30585:bbdd0c2f-1337000:aO5vhWTx', 'unlock_tw_3_1': '93.190.142.57:22671:b5ffe0bf-1215089:WGP1e5TQ', 'unlock_tw_3_2': '89.38.99.29:34263:9cd196f1-1340678:aT01m5q7', 'unlock_tw_3_3': '109.236.80.35:40988:a0b49ce4-1309404:dtdlx8MK', 'unlock_tw_3_4': '89.38.98.87:47958:f2421159-760396:qdEuKwuR', 'unlock_tw_3_5': '62.112.11.204:32040:f6bfe4cf-1186459:HhPuSHuH', 'unlock_tw_3_6': '62.112.11.204:29629:f4055523-1184048:uopjyM0b', 'unlock_tw_3_7': '185.2.81.74:26438:ded7be86-1256855:jdmFRFLa', 'unlock_tw_3_8': '185.2.81.74:27309:7054d2db-1257726:6QwYqrNL', 'unlock_tw_3_9': '93.190.142.57:26363:13a4fe7d-1218781:U1VNIu1a', 'unlock_tw_3_10': '62.112.11.204:32911:7a573e1e-1187330:MOsDD9gv', 'unlock_tw_3_11': '109.236.80.35:36369:014ebc08-1304785:tWeBZ4yP', 'unlock_tw_3_12': '89.38.99.29:27189:51353b56-1333604:FwuHYwKU', 'unlock_tw_3_13': '93.190.142.57:41966:87075df0-1234384:alKIRHjz', 'unlock_tw_3_14': '185.2.81.74:20616:8e7a2689-1251033:l2h0VEzy'}

else:
    asocks={}
    for i in range(1,4):
        for j in range(15):
    # for i in range(1,2):
    #     for j in range(1,2):
            cu=f'unlock_tw_{i}_{j}'
            # rtg=[]
            # try:
            #     rfd=requests.get('https://api.asocks.com/v2/dir/countries?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp')
            #     for jiji in rfd.json()['countries']:
            #         rtg.append(jiji['code'])

            # except Exception as zxc:
            #     print(repr(zxc))
            #     rtg=["BR",'DE','SA']

            rtg=["BR",'SA']

            pay={"name":cu,"type_id":3,"method_rotate":'ever_request',"timeout":None,"auth_type_id":2,"country_code":random.choice(rtg),"state":None,"city":None,"asn":None,"proxy_type_id":1,"id":1}
            
            try:
                r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp',json=pay,timeout=15)
                #print(r.text)
                passp=r.json()['data']['password']
            except:
                r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp',json=pay,timeout=15)
                #print(r.text)
                passp=r.json()['data']['password']
            if passp==None:
                passp=''
            else:
                passp=str(passp)
            proxystr=str(r.json()['data']['server'])+":"+str(r.json()['data']['port'])+":"+str(r.json()['data']['login'])+":"+passp

            proxys={
                                                                    "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                            }

            asocks[cu]=proxystr

    print(asocks)

    raise Exception('?')


global_dop_system=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
class TlsAdapter(HTTPAdapter):
    def __init__(self, ssl_options=0, **kwargs):
        self.ssl_options = ssl_options
        super(TlsAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = create_urllib3_context(ciphers=CIPHERS, cert_reqs=ssl.CERT_REQUIRED, options=self.ssl_options)
        self.poolmanager = PoolManager(*pool_args, ssl_context=ctx, **pool_kwargs)


class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def create_ssl_context(self):
        #ctx = create_urllib3_context(ciphers=FORCED_CIPHERS)
        ctx = ssl.create_default_context()
        # allow TLS 1.0 and TLS 1.2 and later (disable SSLv3 and SSLv2)
        #ctx.options |= ssl.OP_NO_SSLv2
        #ctx.options |= ssl.OP_NO_SSLv3 
        #ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_2
        ctx.options |= ssl.OP_NO_TLSv1_1
        #ctx.options |= ssl.OP_NO_TLSv1_3
        ctx.set_ciphers( CIPHERS )
        #ctx.set_alpn_protocols(['http/1.1', 'spdy/2'])
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)



CONSUMER_KEY = 'Om6JtyI4Ra1bKXXfDLsdPTA0f'                             # Consumer Key
CONSUMER_SECRET = 'c2FjABXssw33ryeXYZexqhP6At2CgODB43XIef85TuIOqPjm5t'         # Consumer Secret
ACCESS_TOKEN = '1533260702068183040-7uhMpA3AHJYQWw0HE96cjFswKpEXPw' # Access Token
ACCESS_TOKEN_SECRET = 'VSCMmnJ2u39Hb3yTHHhqywHf8JXpEL9JpktOofNobsCAc'         # Accesss Token Secert
twitter = OAuth1Session(CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

lock = threading.Lock()

curcur=0
with open('apik.txt','r') as apikc:
    apikk=apikc.readlines()
apik=[]
for ik in apikk:
    apik.append(ik.replace('\n','')) 


default=input('default? - ')
if default=='t':
    default=True
else:
    default=False

def get_csrf_twitter(head,proxy):
    headd=head
    for i in range(5):
        head=headd
        try:
            head['upgrade-insecure-requests']= '1'
            head['accept']= 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
            head['accept-encoding']= 'gzip, deflate, br'
            head['sec-fetch-dest']= 'document'
            head['sec-fetch-mode']= 'navigate'
            head['sec-fetch-site']= 'cross-site'
            head['sec-fetch-user']= '?1'
            
            r = requests.get(r'https://twitter.com/Twitter?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor',headers=head,proxies=proxy, allow_redirects=False)
            #print(dict(r.cookies))
            guest_id = dict(r.cookies)['guest_id'][5:]
            connect_hash = dict(r.headers)['x-connection-hash']
            try:
                cookie_match = re.search(r'gt=(\d+)', r.text)
                gt_token = cookie_match.group(1)
            except:
                try:
                    gt_token = dict(r.cookies)['gt']
                except:
                    head['authorization']= 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
                    head['x-twitter-active-user']= 'yes'
                    head['origin']= 'https://twitter.com'
                    head['referer']= 'https://twitter.com/'

                    r = requests.post('https://api.twitter.com/1.1/guest/activate.json',headers=head,proxies=proxy, cookies=r.cookies.get_dict())
                    gt_token=r.json()['guest_token']
            #print(gt_token)
            csrf = hashlib.md5(connect_hash.encode('utf-8')).hexdigest()
            break
        except Exception as x:
            
            print(repr(x),'getting csrf',proxy)
            time.sleep(2)

    return {'x-csrf-token': csrf, 'x-guest-token': gt_token, 'guest_id': guest_id}


lcc=['Berlin','ETH','Paris','Researching','Ukraine','No Wars !','Grinding','Searching','The Moon', 'Pakistan','Mexico','Egypt','Brazil','Old times','Konokha','UK','Degen','Degen Town','WAGMI','Solana','Jpeg','JPEG','Imaginary','Future','Cyberpunk','2077','Discord','Dota2','Game','coding','Senegal','Chile','chill','Sri Lanka','Cameroon','Lebanon','Burkina Faso']
# with open('loc.txt','r') as lcr:
#     lcr=lcr.readlines()
# lcc.extend(lcr)
uc=['1381699264011771906','1416070452372459523','1478769546207006720','1491285218422300673','1486748711883583490','1457443615542636545','1432583226707484676','946213559213555712',"1468039701642629122",'1478581829271654400','1367095024069062657','2621412174']
tc=['1508915008704421890','1518440912078004224','1531342238147612672','1526359246476132352','1531689518856011777','1531321737820139520','1509570512426569729','1523670750473101313','1509602586147631105','1532502611038851072','1531647849599057921','1532738011242409989','1526408320944418816','1531562762962337793','1502939843386830852','1533223397458468866']

proxy_id=input('id - ')
do_mail=input('CRETE OUTLOOK? - ')
if do_mail=='f':
    do_mail=True
else:
    do_mail=False
do_phone=input('add phone ? - ')
if do_phone=='t':
    do_phone=True
else:
    do_phone=False
if default:
    farm=False
else:
    farm=input('farm? t/f - ')
    if farm=='t':
        farm=True
    else:
        farm=False
        
lls=None

#if proxy_id.replace(' ','')!='':
proxylist='''185.132.133.232:25764:325dd49d-428214:PFtD3jpU
185.132.177.55:29664:a64ef41d-152096:gIww4huV
190.2.155.30:29663::6e130ef4-492111:Ku4z3ynn
190.2.155.30:29631:9f3bd216-492079:9eBSJEkZ
185.132.133.232:29665:3cbb3b1c-432115:HL5VVBcy
185.132.133.232:26469:0dca6eeb-428919:TwrgzJnU
geo.iproyal.com:12321:twitus:twituspassos202
geo.iproyal.com:12321:twitus:twituspassos202
geo.iproyal.com:12321:twitus:twituspassos202
geo.iproyal.com:12321:twitus:twituspassos202'''.split('\n')

#if True:
if proxy_id.replace(' ','')!='':
    px=0
    while True:
        try:
            headd={'Authorization': 'Bearer 1a26731306610ee2c93a2a3af9c6e30e','User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36'}

            r=requests.get(f'https://mobileproxy.space/api.html?command=get_my_proxy&proxy_id={proxy_id}',headers=headd)
            if len(r.json()[0]['proxy_geo'].split(',')[0])==7:
                cr=1
            else:
                cr=0

            proxyforanti=r.json()[0]['proxy_independent_http_host_ip']
            #proxystr=f"{r.json()[0]['proxy_hostname']}:{r.json()[0]['proxy_http_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
            proxystr=f"{r.json()[0]['proxy_independent_http_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
            
            proxysocks=f"{r.json()[0]['proxy_independent_socks5_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
            lls=r.json()[0]['proxy_change_ip_url']
            proxys={
                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                }
            proxystr=proxystr



            proxystr_for_dr=proxystr
            if False:
                pay={"name":"1","type_id":3,"method_rotate":None,"timeout":None,"auth_type_id":1,"country_code":"US","state":None,"city":None,"asn":None,"proxy_type_id":3,"id":1}
                try:
                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                    #print(r.text)
                    passp=r.json()['data']['password']
                except:
                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                    #print(r.text)
                    passp=r.json()['data']['password']
                if passp==None:
                    passp=''
                else:
                    passp=str(passp)
                proxystr=str(r.json()['data']['server'])+":"+str(r.json()['data']['port'])+":"+str(r.json()['data']['login'])+":"+passp
                #print(proxystr)
                proxys={
                                                                                    "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                            }
            ###
            # proxystr='45.82.65.183:32201:ad7d870b-194651:v2hanttkej'
            # proxys={
            #                                             "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
            #                                     }
            ###    


            proxy=proxys
            print(proxystr)
            pi=proxy_id
            lls=lls
            break
        except Exception as x:
            
            try:
                print(repr(x))
                print(r.text)
            except:
                pass
            px+=1
            if px==4:
                raise Exception('prox xui')
            time.sleep(3)

else:
    proxystr_for_dr=proxylist[0]
#VALID #{'user-agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/735.58 (KHTML, like Gecko) Chrome/90.0.6751.9 Safari/755.32', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'x-csrf-token': 'f596fb3272cef7416d3e2ba1756d110a', 'x-guest-token': '1620105578696609815'}
 #inv      #{'user-agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/202.41 (KHTML, like Gecko) Chrome/53.0.5757.30 Safari/413.61', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'x-csrf-token': 'c93c52bc38bb10f0ce2748429bedce7b', 'x-guest-token': '1620110995740889093'}

#invalid {'user-agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/855.65 (KHTML, like Gecko) Chrome/61.0.5810.54 Safari/315.55', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'x-csrf-token': 'a229efc13f29acd18df51b51ef78eb58', 'x-guest-token': '1620125800572805127'}
#  {'_ga': 'GA1.2.1214543991.1675103070', '_gid': 'GA1.2.1079526017.1675103070', '_twitter_sess': 'BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCMmU7AOGAToMY3NyZl9p%250AZCIlNmNiZGEzOTg3N2JiY2IwNDUyMjJjZTE2NzM5NjYxNTA6B2lkIiVhMjhh%250ANmQ3ZjMyZGVlZmQ3OGQzZTM4NGRhOWIxOWZmMw%253D%253D--5250ef668dc7b43cb269282eda2bf2e583c5b0b2', 'ct0': 'a229efc13f29acd18df51b51ef78eb58', 'gt': '1620125800572805127', 'guest_id': 'v1%3A167510306246916692', 'guest_id_ads': 'v1%3A167510306246916692', 'guest_id_marketing': 'v1%3A167510306246916692', 'personalization_id': '"v1_hEiq2uCX/tfvKPHUByVZwQ=="'}


# with open('farm_ids.txt','r') as fol_acp:
#     fol_acp=fol_acp.readlines()
# fol_acp2=[]
# for accs in fol_acp:
#     fol_acp2.append(accs.replace('\n',''))
# fol_acp=fol_acp2

# random.shuffle(fol_acp)

# follow_list=fol_acp[:random.randint(50,70)]

# curcur=0
# #global apik
# post_list=[]
# lrp=random.randint(250,300)
# fun=0
# keee=True
# sss=requests.Session()
# while len(post_list)<lrp and keee:
#     print(len(post_list),fun,lrp,'post')
#     try:
#         fu=follow_list[fun]
#     except:
#         keee=False
#         fun=0
#     print(fu)
#     try:
#         r=sss.get(f'https://api.twitter.com/2/users/{fu}/tweets?tweet.fields=public_metrics&max_results=100&exclude=replies',headers={"Authorization":f"Bearer {apik[curcur]}"})#,proxies=proxy)
#         if 'Could not find user with id' in r.text:
#             fun+=1
#             raise Exception(f'UDALI NAHUI {fu}')
            
#         if r.json()['meta']['result_count']==0:
#             fun+=1
#             raise Exception(f'UDALI NAHUI {fu}')
#         tdid=r.json()['data']
#         random.shuffle(tdid)
#         randpn=random.randint(7,15)
#         ddd=0
#         for titka in tdid:
#             if ddd<randpn:
#                 if titka['public_metrics']['like_count']>1000 or titka['public_metrics']['retweet_count']>500:
#                     post_list.append(titka['id'])
#                     ddd+=1
#                 else:
#                     #print(titka['public_metrics']['like_count'],titka['public_metrics']['retweet_count'],titka['id'])
#                     pass
#             else:
#                 break

#         asdf=0
#         try:
#             r.json()["meta"]["next_token"]
#             asdd=True
#         except:
#             asdd=False

#         if asdd:
            
#             while True:
#                 try:
#                     if ddd<randpn:
                        
#                         r=sss.get(f'https://api.twitter.com/2/users/{fu}/tweets?tweet.fields=public_metrics&max_results=100&pagination_token={r.json()["meta"]["next_token"]}&exclude=replies',headers={"Authorization":f"Bearer {apik[curcur]}"})#,proxies=proxy)
#                         tdid=r.json()['data']
#                         random.shuffle(tdid)
#                         for titka in tdid:
#                             if ddd<randpn:
#                                 if titka['public_metrics']['like_count']>1000 or titka['public_metrics']['retweet_count']>500:
#                                     post_list.append(titka['id'])
#                                     ddd+=1
#                                 else:
#                                     #print(titka['public_metrics']['like_count'],titka['public_metrics']['retweet_count'],titka['id'])
#                                     pass
#                             else:
                                
#                                 break
                        
#                     else:
#                         break
#                 except Exception as x:
#                     print(repr(x))
                
#                 asdf+=1
#                 if asdf>4:
#                     fun+=1
#                     raise Exception(f'UDALI NAHUI {fu}')
#         if ddd<randpn:
#             fun+=1
#             raise Exception(f'UDALI NAHUI {fu}')
#         fun+=1
#     except Exception as x:
        
        
#         try:
#             print(r.text)
#         except:
#             pass

#         print(r)
#         print(apik[curcur])
#         print(repr(x))
#     finally:
#         curcur+=1
#         curcur=curcur%len(apik)

# random.shuffle(post_list)
# raise Exception()
def gen_appeal_tex():
    sudushka=random.randint(1,100)
    if sudushka>=50:
        try:
            if False:
                try:
                    response = openai.Completion.create(model="text-davinci-003", prompt="write unique twitter message to the support team about unlocking your accounts and you having problems verifying your phone and you want your account to get unlocked because you are a normal user who did nothing bad. you can be not so formal and might remove greetings or sashtags or might be a little bit angry, but you dont have to, make it random and unique",temperature=0.9, max_tokens=160)
                    text=response['choices'][0]['text'].replace('\n\n','')
                    text = text.encode("utf-8")
                    text = text.decode("utf-8")
                    
                    tex=text.replace('"','')
                except Exception as zxcf:
                    #print(repr(zxcf))
                    sudushka=1
            else:
                with open('/root/work/create_and_unban_SYSTEM/appeals.txt','r') as ap:
                    ap=ap.readlines()
                tex=random.choice(ap)
                if '[' in tex:
                    rr=tex.split('[')[-1]
                    rl=rr.split(']')[0]
                    tex=tex.replace(f", [{rl}]",'')
                    tex=tex.replace(f". [{rl}]",'')
                    tex=tex.replace(f"[{rl}]",'')
                if '@' in tex:
                    rr=tex.split('@')[-1]
                    rl=rr.split(' ')[0]
                    tex=tex.replace(f"@{rl}",random.choice(['twitter ','','','Twitter '])+random.choice(['','support','support team','mods','moderators','admins']))
                
                tex=tex.replace('\n','')
                tex=tex.replace(r'#\n','\n')
        except Exception as x:
            print(repr(x))
            sudushka=1

    if sudushka<50:

        hel=random.choice(['hello','hi','Hey','sup','yo'])+random.choice([' there','','',''])+random.choice(['.',',','\n'])+random.choice(['\n',' ',''])+' '
        if random.randint(1,100)>50:
            hel=hel.title()
        hel=hel+random.choice([f' listen{random.choice([",",""])}','',''])
        hel=random.choice(['',hel])


        tochk=random.choice(['.',',','!',''])+random.choice([' ',''])
        if tochk=='':
            tochk=' '

        tochk2=random.choice(['.',',','!'])+random.choice([' ',''])

        end=random.choice(['.','!','!!','...','',''])
        fhf=f'pls{random.choice([" ",""])}'
        pls=random.choice(['pls',"please",f"{random.randint(1,3)*fhf}",f"{random.choice(['I am',''])} begging {random.choice(['you',''])} {random.choice(['to',''])}","",])
        pls2=random.choice(['pls',"please",f"{random.randint(1,3)*fhf}",f"{random.choice(['I am',''])} {random.choice(['begging','asking','indeed','requesting'])} {random.choice(['you',''])} {random.choice(['to',''])}","",])


        mbis=random.choice(["must be","is",])+'::'+random.choice(["most likely","for sure",'100%'])+random.choice([""," is"])
        mbis=mbis.split('::')
        random.shuffle(mbis)
        mbis=' '.join(mbis)
        err=random.choice([f"that {mbis} miss",f"it {mbis} an error",""])


        prizid=random.choice(["so ",tochk2,' '])+random.choice(["unlock","unban","set free","restore","revive"])+random.choice([" me",f" my acc{random.choice(['ount',''])}",f"the acc{random.choice(['ount',''])}",''])

        dop=random.choice(["why?","what?","wtf?",'how is it possible?',"how that happend?",'','','','',''])

        dop2=random.choice([f"no way","impossible","unbelievable","crazy"])+random.choice(['!','...',', ','.'])
        dop2=random.choice([dop2,''])

        oprav=random.choice(["I cant verify my phone","I struggle with phone verification","cant get my phone to an account","I cant verify my phone","I struggle with phone verification","cant get my phone to an account","cant recieve sms","there are some problems with sms verification","It doesnt let me recieve sms on my phone"])
        

        if random.randint(1,100)>50:
            opravdop=f'{random.choice(["+","and","also","by the way"])} I {random.choice(["did nothing suspicious","was acting normal","was doing regular stuff"])}'
            opravdop2=random.choice([f"I am{random.choice([' just',''])} {random.choice([' a',''])} {random.choice(['new','regular','normal','typical','random'])} {random.choice(['user','guy','person','one','transgender','user','man','user','user'])}",''])+tochk
            opravdop=random.choice([opravdop,opravdop2])
            oprav=oprav+tochk+' '+opravdop


        
        naezd=random.choice(["let people free","deal with it","fix your algorythms","cant even act normal, fix this please","could you make sure it won`t happen again pls?",f'{random.choice(["make sure","control that"])} {random.choice(["this","it"])} doesnt happen again',f'Fix {random.choice(["this","it"])}',f'deal with {random.choice(["this","it"])}','save me',f'let me use {random.choice(["your app","it"])}'])
        naezd=naezd+random.choice(['!','',''])

        poka=random.choice(['Thank you','Thanks'])+' '+random.choice(['in advance',''])
        poka=random.choice([poka,''])

        ter=[pls,err,prizid,dop,dop2,oprav,pls2]
        ter2=[]
        for jijig in ter:
            if random.randint(1,100)>90:
                ter2.append(jijig.upper())
            else:
                ter2.append(jijig)

        pls=ter2[0]
        err=ter2[1]
        prizid=ter2[2]
        dop=ter2[3]
        dop2=ter2[4]
        oprav=ter2[5]
        pls2=ter2[6]

        if random.randint(1,100)>70:
            naezd=naezd.upper()



        tot=[tochk,pls+' '+prizid,err,oprav,tochk]
        while tot[0]==tochk and tot[-1]==tochk:
            random.shuffle(tot)

        tot=' '.join(tot)

        meh=random.choice(["\n",'\n\n',' '])
        if random.randint(1,100)>35:
            tex=f'{hel}{dop} {dop2} {tot}. {pls2} {naezd}{end}{meh}{poka}'
        else:
            naezd=random.choice([naezd,'',naezd])
            err=random.choice([err,'',err])
            tochk=random.choice([tochk,''])
            dop=random.choice([dop,'',dop])
            tex=f'{naezd} {oprav} {err} {dop} {tochk}'

        #tex=f'{hel}{random.choice(["why",""])} {random.choice(["please",""])} {random.choice(["pls","I am begging"])} {random.choice(["unlock","unban"])} {random.choice([" thats miss",""])} {random.choice(["it is an error",""])} {random.choice([f"I am new user","I am just new user","I am new"])} {random.choice(["pls pls psl",""])}'


        #tex = ' '.join(tex.split()).strip()    
        while '  ' in tex:
            tex=tex.replace('  ',' ')
        tex=tex.replace(' .','.')
        for jij in [',','.']:
            tex=tex.split(jij)
            try:
                tex.remove(' ')
            except:
                pass
            tex=jij.join(tex)

        tex=tex.replace(',.',random.choice([',','.'])).replace(',,',',').replace('..','.').replace('.,',random.choice([',','.']))

    return tex

ersin=0
trap=0
def changecr(pid=None):
    if pid==None:
        global lls
        if lls and lls!='None':
            
            global pi
            global proxy
            global proxystr
            global ersin
            proxy_id=pi

    if type(pid)==int or pid==None:
        if type(pid)==int:
            proxy_id=pid

        if lls and lls!='None':
            if pi!='None':
                if ersin>=2:

                            xxqwe=0
                            while True:
                                try:
                                    
                                    
                                    headd={'Authorization': 'Bearer 1a26731306610ee2c93a2a3af9c6e30e','User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36','Connection':'close'}

                                    r=requests.get(f'https://mobileproxy.space/api.html?command=get_geo_list&proxy_id={proxy_id}',headers=headd)
                                    geoids=[]
                                    global cr
                                    if cr==1:
                                        gf='UA'
                                    elif cr==0:
                                        gf='KZ'
                                    else:
                                        gf='UA'
                                    for i in r.json():
                                        if i['iso']==gf and i['count_free']!='0':
                                            geoids.append(i['geoid'])
                                            
                                    geoid=random.choice(geoids)


                                    r=requests.get(f'https://mobileproxy.space/api.html?command=change_equipment&geoid={geoid}&proxy_id={proxy_id}&add_to_black_list=0',headers=headd)

                                    #r=requests.get(f'https://mobileproxy.space/api.html?command=proxy_ip&proxy_id={proxy_id}',headers=head)
                                    r=requests.get(f'https://mobileproxy.space/api.html?command=get_my_proxy&proxy_id={proxy_id}',headers=headd)
                                    proxyforanti=r.json()[0]['proxy_independent_http_host_ip']
                                    
                                    #proxystr=f"{r.json()[0]['proxy_hostname']}:{r.json()[0]['proxy_http_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                                    proxystr=f"{r.json()[0]['proxy_independent_http_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                
                                    proxysocks=f"{r.json()[0]['proxy_independent_socks5_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                
                                    lls=r.json()[0]['proxy_change_ip_url']
                                    proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
                                    
                                    proxystr=proxystr
                                    lls=lls
                                    global proxystr_for_dr
                                    proxystr_for_dr=proxystr


                                    ###
                                    # proxystr='190.2.155.30:25665:e81e5673-488113:selat87ohrs'
                                    # proxys={
                                    #                                             "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                    #                                     }
                                    ###


                                    proxy=proxys
                                    print(proxystr)
                                    ersin=0
                                    break
                                except Exception as x:
                                    try:
                                        print(repr(x))
                                    except:
                                        pass
                                    try:
                                        print(r.text)
                                    except:
                                        pass
                                    try:
                                        r.text
                                    except:
                                        pass
                                    xxqwe+=1
                                    time.sleep(5)
                                    if xxqwe==4:
                                        #raise Exception('geo not changing')
                                        print('geo not changing')
                                        break
                        


            while True:
                try:
                    r=requests.get(lls, headers={'User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36'})
                    if r.status_code==200:
                        print('changed')

                        break
                except Exception as x:
                    #
                    try:
                        if 'Too many same requests' in r.text:
                            break
                    except:
                        pass
                    print(repr(x))
                    time.sleep(2)

            px=0

            while True:
                try:
                    headd={'Authorization': 'Bearer 1a26731306610ee2c93a2a3af9c6e30e','User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36'}

                    r=requests.get(f'https://mobileproxy.space/api.html?command=get_my_proxy&proxy_id={proxy_id}',headers=headd)
                    if len(r.json()[0]['proxy_geo'].split(',')[0])==7:
                        cr=1
                    else:
                        cr=0


                    proxyforanti=r.json()[0]['proxy_independent_http_host_ip']
                    #proxystr=f"{r.json()[0]['proxy_hostname']}:{r.json()[0]['proxy_http_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                    proxystr=f"{r.json()[0]['proxy_independent_http_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                
                    proxysocks=f"{r.json()[0]['proxy_independent_socks5_hostname']}:{r.json()[0]['proxy_independent_port']}:{r.json()[0]['proxy_login']}:{r.json()[0]['proxy_pass']}"
                    lls=r.json()[0]['proxy_change_ip_url']
                    proxys={
                                                                "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                        }
                    proxystr=proxystr



                    proxystr_for_dr=proxystr
                    if False:
                        pay={"name":"1","type_id":3,"method_rotate":None,"timeout":None,"auth_type_id":1,"country_code":"US","state":None,"city":None,"asn":None,"proxy_type_id":3,"id":1}
                        try:
                            r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                            #print(r.text)
                            passp=r.json()['data']['password']
                        except:
                            r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                            #print(r.text)
                            passp=r.json()['data']['password']
                        if passp==None:
                            passp=''
                        else:
                            passp=str(passp)
                        proxystr=str(r.json()['data']['server'])+":"+str(r.json()['data']['port'])+":"+str(r.json()['data']['login'])+":"+passp
                        #print(proxystr)
                        proxys={
                                                                                            "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                    }
                    ###
                    # proxystr='45.82.65.183:32201:ad7d870b-194651:v2hanttkej'
                    # proxys={
                    #                                             "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                    #                                     }
                    ###    


                    proxy=proxys
                    print(proxystr)
                    pi=proxy_id
                    lls=lls
                    break
                except Exception as x:
                    
                    try:
                        print(repr(x))
                        print(r.text)
                    except:
                        pass
                    px+=1
                    if px==4:
                        raise Exception('prox xui')
                    time.sleep(3)

    else:
        pass
            

def system_check_start(fa,m=True):

        if m:
            MAIL=fa.split(':')[2]
            MPASS=fa.split(':')[3]
            if '@gmx' in MAIL:
                typegh='gmx'
            elif '@gmail' in MAIL:
                typegh='gmail'
            elif '@outlook' in MAIL or '@hotmail' in MAIL:
                typegh='hot'
            elif '@mail' in MAIL:
                typegh='mail'
            elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                typegh='rambler'

            try:
                mm=mmail.mail_by_login(MAIL,MPASS,typegh)
            except Exception as x:
                if 'KeyboardInterrupt' in str(x):
                    dn='KeyboardInterrupt'
                    raise Exception('KeyboardInterrupt')
                else:
                    print(repr(x),'system login mail',MAIL,MPASS)
                    # global ersin
                    # ersin-=1
                    dn='mail_ban'
                    raise Exception('mail ban')

        head={}
        
        head['User-Agent']=fa.split(':')[4]
        try:
            cookies=':'.join(fa.split(':')[5:-2])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
            cookies=json.loads(cookies)
        except Exception as x:
                try:
                    cookies=':'.join(fa.split(':')[5:-2]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                    cookies=json.loads(cookies)
                except Exception as x:
                    try:
                        cookies=':'.join(fa.split(':')[5:-1])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                        cookies=json.loads(cookies)
                    except Exception as x:
                        try:
                            cookies=':'.join(fa.split(':')[5:-1]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                            cookies=json.loads(cookies)
                        except Exception as x:
                            try:
                                cookies=':'.join(fa.split(':')[5:]).replace('\n','')#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                cookies=json.loads(cookies)
                            except Exception as x:
                                try:
                                    cookies=':'.join(fa.split(':')[5:]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false').replace('\n','')
                                    cookies=json.loads(cookies)
                                except Exception as x:
                                    try:
                                        cookies=':'.join(fa.split(':')[6:-2])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false').replace('\n','')
                                        cookies=json.loads(cookies)
                                        head['User-Agent']=fa.split(':')[5]
                                    except Exception as x:
                                        print(repr(x))
                                        print(':'.join(fa.split(':')[5:-2]))
                                        raise Exception(f"ERROR COOKIES FORMAT {fa.split(':')[0]}")
        head['Connection']= 'close'
        cc=[]
        try:
            head['x-csrf-token']=cookies['ct0']
        except:
            pass

        try:
            cal={}
            for cookie in cookies:
                    if cookie['name']=='ct0':
                        head['x-csrf-token']=cookie['value']
                    cc.append(f"{cookie['name']}={cookie['value']}")
                    cal[cookie['name']]=cookie['value']
            cc='; '.join(cc)
            
            head['cookie']=cc
            cookies=cal
            
        except:
            #print(cookies)
            #head['cookie']=json.dumps(cookies)[1:-1]
            pass
        
        head["authorization"]='Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA' 
        if m:

            return head,mm,cookies
        else:
            return head,cookies
changed=False
dong=0
tgt=[]


def twit(head,cookies):
    wers=0
    media_id=None
    medka=False
    
    if True:
        while True:
            while True:
                # hcp=random.randint(1,100)
                # if hcp>70:
                #     sp=f'av/{random.choice(os.listdir(r"av"))}'
                #     #gf=random.choice(os.listdir(r"D:\pictures\ins"))
                #     #sp=f'D:\pictures\ins\{gf}'
                    
                # else:
                    
                sp=f'pics/{random.choice(os.listdir(r"pics"))}'
                    #gf=random.choice(os.listdir(r"D:\pictures\ins"))
                    #sp=f'D:\pictures\ins\{gf}'
                sp1=f'pics/{random.choice(os.listdir(r"pics"))}'
                sp2=f'banners/{random.choice(os.listdir(r"banners"))}'
                sp3=f'av/{random.choice(os.listdir(r"av"))}'
                
                sp=random.choice([sp1,sp2,sp3])
                if '_hex' not in sp:
                    break
            mgm=open(sp, 'rb')
            files = {"media" : mgm}
            
            
            try:
                
                #media_idd = twitter.post(f'https://upload.twitter.com/1.1/media/upload.json?additional_owners={uidm}', files = files, proxies=proxy)
                #media_id=media_idd.json()['media_id_string']
                rf=requests.post('https://upload.twitter.com/1.1/media/upload.json?media_category=tweet_image',files = files,headers=head,cookies=cookies,timeout=15
                #,proxies=proxych
                )
                #r.close() 
                media_id=rf.json()['media_id_string']
                mgm.close()
                break
            except:
                #print(rf.text)
                wers+=1
                if wers>1:
                    mgm.close()
                    #print('CHOTO S MEDIA XZ FARmm')
                    return rf
    
    else:
        media_id=False

    if media_id!=None:
        sud=random.randint(1,100)
        #sud=random.randint(0,4)
        if sud>50:
            
            ssf=''
            while ssf=='':
                for gjj in range(3):
                    sud=random.randint(1,100)
                    if sud>80:
                        sashnft=['NFT','ETH','BTC','ART','NFTArt','NFTCommunity','Crypto','CryptoCommunity','NFTComunity','CryptoCommunity','Solana','SOL','Aptos','BNB']
                        random.shuffle(sashnft)
                        ssgh=randint(1,5)
                        if ssgh!=0:
                            #ssgh='#'+' #'.join(sashnft[:ssgh])
                            #toaarara=random.choice(['#',''])
                            toaarara='#'
                            ssgh=f' {toaarara}'+f' {toaarara}'.join(sashnft[:ssgh])
                            
                            ssgh=random.choice(['\n','\n\n',' '])+ssgh
                        else:
                            ssgh=''
                        ssf+=ssgh
                    elif sud>40:
                        smlsd=[':eye_in_speech_bubble:',':red_heart:',':pill:',':wrench:',':camera_with_flash:',':hundred_points:',':purple_heart:',':green_heart:',':yellow_heart:',':black_heart:',':kiss_mark:',':alien:',':police_car_light:',':airplane:',':fire:',':comet:',':snowflake:',':high_voltage:',':umbrella_with_rain_drops:',':party_popper:',':wrapped_gift:',':trophy:',':crown:',':drop_of_blood:',':shinto_shrine:',':beer_mug:',':cut_of_meat:',':four_leaf_clover:',':spider_web:',':hamster:',':folded_hands:']
                        random.shuffle(smlsd)
                        asdd=random.randint(-3,3)
                        if asdd<1:
                            asdd=1
                        trt=smlsd[:asdd]
                        trtd=[]
                        for pspsp in trt:
                            trtd.append(emoji.emojize(pspsp))


                        ssf2=random.choice(['',' ','']).join(trtd)

                        if asdd==1:
                            asdd=random.randint(-1,3)
                            if asdd<1:
                                asdd=1
                            ssf2=f" {ssf2}{random.choice(['',' ',''])}"*asdd
                        ssf+=ssf2
        else:
            tex=''
            while tex.replace(' ','')=='' or len(tex)>=250:
                try:
                    with open('bios_gpt.txt','r') as acpb:
                        acpb = acpb.readlines()
                        
                    tex=acpb[randint(0,len(acpb))].encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                    tex=tex.replace('\n','')
                    tex=tex.replace(r'#\n','\n')
                    
                except:
                    with open('bios_gpt.txt','rb') as acpb:
                        acpb = acpb.readlines()
                        
                    tex=acpb[randint(0,len(acpb))].decode().encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                    tex=tex.replace('\n','')
                    tex=tex.replace(r'#\n','\n')
                
            ssf=tex

        ssf=ssf.replace('#',random.choice(['','#']))
        
        try:
            ssf=ssf.strip()
        except:
            pass

        if medka or random.randint(1,100)>70:
        #if media_id:
        
            aa='yL4KIHnJPXt-JUpRDrBDDw' 
            pay={"variables":{"tweet_text":ssf,"dark_request":False,"media":{"media_entities":[{"media_id":media_id,"tagged_users":[]}],"possibly_sensitive":False},"withDownvotePerspective":False,"withReactionsMetadata":False,"withReactionsPerspective":False,"withSuperFollowsTweetFields":True,"withSuperFollowsUserFields":True,"semantic_annotation_ids":[]},                     "features":{"view_counts_public_visibility_enabled":True,"view_counts_everywhere_api_enabled":True,"longform_notetweets_consumption_enabled":False,"tweetypie_unmention_optimization_enabled":True,"responsive_web_uc_gql_enabled":True,"vibe_api_enabled":True,"responsive_web_edit_tweet_api_enabled":True,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":True,"interactive_text_enabled":True,"responsive_web_text_conversations_enabled":False,"responsive_web_twitter_blue_verified_badge_is_enabled":True,"verified_phone_label_enabled":False,"standardized_nudges_misinfo":True,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":False,"responsive_web_graphql_timeline_navigation_enabled":True,"responsive_web_enhance_cards_enabled":False},"queryId":aa}
            zxc=0
            
            while True:
                try:            
                    rf=requests.post(f'https://twitter.com/i/api/graphql/{aa}/CreateTweet',timeout=15,json=pay,headers=head,cookies=cookies)
                    return rf
                except Exception as x:
                    print(repr(x))
                    zxc+=1
                    if zxc>3:
                        raise Exception(x)
        else:

            aa='ADqGYPOhoHnTSqf6K9CqOQ' 
            #pay={"variables":{"tweet_text":ssf,"dark_request":False,"media":{"media_entities":[{"media_id":media_id,"tagged_users":[]}],"possibly_sensitive":False},"withDownvotePerspective":False,"withReactionsMetadata":False,"withReactionsPerspective":False,"withSuperFollowsTweetFields":True,"withSuperFollowsUserFields":True,"semantic_annotation_ids":[]},                     "features":{"view_counts_public_visibility_enabled":True,"view_counts_everywhere_api_enabled":True,"longform_notetweets_consumption_enabled":False,"tweetypie_unmention_optimization_enabled":True,"responsive_web_uc_gql_enabled":True,"vibe_api_enabled":True,"responsive_web_edit_tweet_api_enabled":True,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":True,"interactive_text_enabled":True,"responsive_web_text_conversations_enabled":False,"responsive_web_twitter_blue_verified_badge_is_enabled":True,"verified_phone_label_enabled":False,"standardized_nudges_misinfo":True,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":False,"responsive_web_graphql_timeline_navigation_enabled":True,"responsive_web_enhance_cards_enabled":False},"queryId":aa}
            pay={"variables":{"tweet_text":ssf,"dark_request":False,"media":{"media_entities":[],"possibly_sensitive":False},"withDownvotePerspective":False,"withReactionsMetadata":False,"withReactionsPerspective":False,"semantic_annotation_ids":[]},"features":{"tweetypie_unmention_optimization_enabled":True,"vibe_api_enabled":True,"responsive_web_edit_tweet_api_enabled":True,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":True,"view_counts_everywhere_api_enabled":True,"longform_notetweets_consumption_enabled":True,"tweet_awards_web_tipping_enabled":False,"interactive_text_enabled":True,"responsive_web_text_conversations_enabled":False,"longform_notetweets_richtext_consumption_enabled":False,"responsive_web_twitter_blue_verified_badge_is_enabled":True,"responsive_web_graphql_exclude_directive_enabled":True,"verified_phone_label_enabled":False,"freedom_of_speech_not_reach_fetch_enabled":False,"standardized_nudges_misinfo":True,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":False,"responsive_web_graphql_timeline_navigation_enabled":True,"responsive_web_graphql_skip_user_profile_image_extensions_enabled":False,"responsive_web_enhance_cards_enabled":False},"queryId":aa}
            zxc=0
            
            while True:
                try:            
                    rf=requests.post(f'https://twitter.com/i/api/graphql/{aa}/CreateTweet',timeout=15,json=pay,headers=head,cookies=cookies)
                                    
                    return rf
                except Exception as x:
                    print(repr(x))
                    zxc+=1
                    if zxc>3:
                        raise Exception(x)
    else:
        return False

    print(f'NAKRuTILI P')
    

def follow(head,uid,cookies):
    zxczxc=0
    while True:
        head['Connection']='close'
        pay=f'include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&include_ext_has_nft_avatar=1&include_ext_is_blue_verified=1&include_ext_verified_type=1&skip_status=1&user_id={uid}'  
        try:
            rf=requests.post('https://twitter.com/i/api/1.1/friendships/create.json',params=pay,headers=head,timeout=60,cookies=cookies)#,proxies=proxy)
            
            #rf=requests.post('https://api.twitter.com/1.1/friendships/create.json',params=pay,headers=head,timeout=60,cookies=cookies,proxies=proxy)#,verify=False)#
        except Exception as x:
            print(repr(x))
            time.sleep(1)
            try:
                rf=requests.post('https://twitter.com/i/api/1.1/friendships/create.json',params=pay,headers=head,timeout=60,cookies=cookies)#,proxies=proxy)
                #rf=requests.post('https://api.twitter.com/1.1/friendships/create.json',params=pay,headers=head,timeout=60,cookies=cookies,proxies=proxy)#verify=False)#
            except Exception as x:
                print(repr(x))
                raise Exception('idk wtf 2')

        if rf.text!='{"errors":[{"code":108,"message":"Cannot find specified user."}]}':
            if rf.text.replace(' ','')=='':
                zxczxc+=1
                if zxczxc>2:
                    raise Exception('HUITA S HEADERAMI')
            else:
                break                                
        else:
            with open('farm_ids.txt','r') as fid:
                fid=fid.readlines()
            uid=random.choice(fid)
            uid=uid.replace('\n','')
            print(uid,'NEW UID TO FOLLOW')
    return rf

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def cryptojs_encrypt(data, key):
    # Padding
    data = data + chr(16-len(data)%16)*(16-len(data)%16)

    salt = b"".join(random.choice(string.ascii_lowercase).encode() for x in range(8))
    salted, dx = b"", b""
    while len(salted) < 48:
        dx = hashlib.md5(dx+key.encode()+salt).digest()
        salted += dx

    key = salted[:32]
    iv = salted[32:32+16]
    aes = AES.new(key, AES.MODE_CBC, iv)

    encrypted_data = {"ct": base64.b64encode(aes.encrypt(data.encode())).decode("utf-8"), "iv": iv.hex(), "s": salt.hex()}
    return json.dumps(encrypted_data, separators=(',', ':'))


def cryptojs_decrypt(data, key):
    data = json.loads(data)
    #print(data)
    dk = key.encode()+bytes.fromhex(data["s"])

    md5 = [hashlib.md5(dk).digest()]
    result = md5[0]
    for i in range(1, 3+1):
        md5.insert(i, hashlib.md5((md5[i-1]+dk)).digest())
        result += md5[i]

    #print(bytes.fromhex(data["iv"]))
    
    aes = AES.new(result[:32], AES.MODE_CBC, bytes.fromhex(data["iv"]))
    data = aes.decrypt(base64.b64decode(data["ct"]))
    return data

def get_xy():
    if False:
        start_pos = [117, 248]
        button_size = [90, 28]
        new_pos = [
            start_pos[0] + random.randint(1, button_size[0]),
            start_pos[1] + random.randint(1, button_size[1])]
    else:
        start_pos = [300, 400]
        button_size = [50, 28]
        new_pos = [
            start_pos[0] + random.randint(1, button_size[0]),
            start_pos[1] + random.randint(1, button_size[1])]
    return new_pos


def update_metadata(origin, metadata,key=None,value=None):

        if False:
            if origin == "ekey" and not metadata.get("sc"):
                metadata["sc"] = get_xy()
            
            elif origin == "guess" and not metadata.get("dc"):
                metadata["dc"] = get_xy()
            
            elif origin == "lastguess" and value:
                gg=[]
                if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
                    print(value)
                    gg.append(value)
                

                elif key=='B7D8911C-5CC8-A9A3-35B0-554ACEE604DA':
                    gg.append(value)

                elif False:
                    gss.append([int(answer)])
                #gg.append({'index':int(value)})
                g=(gg)#.replace(' ','')
                metadata["ech"] = g
        else:
            
            if origin == "ekey" and not metadata.get("dc"):
                metadata["dc"] = get_xy()
            
            elif origin == "guess" and not metadata.get("sc"):
                metadata["sc"] = get_xy()
            
            elif origin == "lastguess" and value:
                gg=[]
                if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
                    print(value)
                    gg.append(value)
                

                elif key=='B7D8911C-5CC8-A9A3-35B0-554ACEE604DA':
                    gg.append(value)

                elif False:
                    gss.append([int(answer)])
                #gg.append({'index':int(value)})
                g=(gg)#.replace(' ','')
                metadata["ech"] = g
        
        return metadata

def get_request_id(session_token,metadata):
       
        key = "REQUESTED" + session_token + "ID"
        data = json.dumps(metadata, separators=(',', ':'))
        return cryptojs_encrypt(data, key)







#rqst=requests.get(f" /get_item?api_key=API_KEY&&db=2&&item_index=4")
#rqst=requests.get(f" /add_item?api_key=API_KEY&&db=2&&new_item=new_item_test")
#rqst=requests.get(f" /delete_item?api_key=API_KEY&&db=2&&item_index=3")
#rqst=requests.get(f" /all_items?api_key=API_KEY&&db=1")





def get_token(db):
    api='createterter'
    

    if False:
        for i in range(3):


            at=requests.get(f'http://83.220.173.239:3002/all_items?api_key={api}&&db={db}').split()
            
            for k in range(len(at)):
                if float(k.split(':')[-1])  +60*5 < time.time():
                    requests.get(f'http://83.220.173.239:3002/delete_item?api_key={api}&&db={db}&&item_index={k+1}')




            while True:
                try:
                    if db=='3':
                        toktok=False
                        token=requests.get(f'http://83.220.173.239:3002/get_item?api_key={api}&&db={db}&&item_index=1')
                        if token.replace('\n','').replace(' ','')=='':
                            requests.get(f'http://83.220.173.239:3002/add_item?api_key={api}&&db={db}&&new_item=GOGOGO')
                            toktok=True
                        elif token.replace('\n','').replace(' ','')=='GOGOGO':       
                            toktok=True
                        
                        if toktok:
                            while True:
                                try:
                                    token=requests.get(f'http://83.220.173.239:3002/get_item?api_key={api}&&db={db}&&item_index=2')
                                    if token.replace('\n','').replace(' ','')!='':
                                        requests.get(f'http://83.220.173.239:3002/delete_item?api_key={api}&&db={db}&&item_index=1')
                                        break
                                    else:
                                        time.sleep(1)

                                except Exception as zxczxc:
                                    print('dvaika',repr(zxczxc))

                                    


                    else:

                        token=requests.get(f'http://83.220.173.239:3002/get_item?api_key={api}&&db={db}&&item_index=1').replace('\n','')
                        requests.get(f'http://83.220.173.239:3002/delete_item?api_key={api}&&db={db}&&item_index=1')
                except Exception as x:
                    print(repr(x))
                    if i>2:
                        raise Exception(x)
        
        return token.split(':')[0]
    else:
        token=input('token = ')
       
        return token

def solvemandef(key='69A21A01-CC7B-B9C6-0F9A-E7FA06677FFC',guru_l=5,proxystr=None):
    metadata={}
    if proxystr==None:
        proxy=None
        
    else:
        try:
            proxy={
                                                                                    "http" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                            }
        except:
            proxy={
                                                                                    "http" : f"https://{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                            }

    print(proxy)
    if False:
        head={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36',
        'Referer': 'https://twitter.com/i/flow/signup',
        
        'Origin': 'https://twitter.com/i/flow/signup'}
        r=requests.post(f'https://roblox-api.arkoselabs.com/fc/gt2/public_key/')
        print(r.text)

        input('')
        requests.post(f'https://api.funcaptcha.com/tile-game-lite-mode/fc/api/nojs/?pkey={key}&lang=ru')
    
    else:

        while True:
            try:
                s=requests.Session()
                

                head={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
                'Referer': f'https://client-api.arkoselabs.com/v2/{key}/enforcement.{random_string()}.html',
                'Origin': 'https://client-api.arkoselabs.com',
                #'cookies':'timestamp=168071700437457',
                #'x-newrelic-timestamp': '168071700587461'
                }

                head["Content-Type"]= "application/x-www-form-urlencoded; charset=UTF-8"
                head["cache-control"]= "no-cache"
                head['x-requested-with']= 'XMLHttpRequest'

                rand_string = ''.join(random.choice('0123456789') for i in range(16))
                bda=get_bda('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',key,head['Referer'],None)
                pay={'bda':
                bda,
                #'eyJjdCI6Imk0NFBtQUVzVFdhcHJYR3JQa2Fvd2VFTU0zMnJQOHVBWGFPbEhRVHJoLzBlL2pKZ2VpZFBsRE9IK1JCcThZZXBYdzVRM2wwS3BTS1dEMlpYaWxrMTRXUmNydy9ES3JJNDlYT2E0ZkZINnZNY3hWYmVFREhGOGg3YUw3TVkzYitFcWpieXJSdG4wWWlpQ1R3L3U4TzYrY0k5aUUyTGdPOGN4UE1zV0xOelpWZmQvcFlHNG9WWkJqT1EyRW96Z3BWdXZPN0RJcUJBbDFKaEVsUjlxU05sWmtWTnBjdVZUcWlMZTFKL2NIbmlLZU5hLzVMK21BNEs2S3kvRU13STNQNXo1aDRoZEtlTmx1TnVUU2hXdldnOU9jU2xpaW5vVFNUWUxad3lMTFZqV09iTXJLVmRNVWlxMGxhUVpJM2V2S2NaclVtczRESzhrR3ByeTNwcFh1aTNnQnpvQ2M0MWJnbXpBZ0lmREh4aTR2VnJJQ1Vsb2dIRFYyMmxrdllKdG1NeDVhQVVaNlh3S1NlQSsydVVXK01Bb1hWeERwYlNlb1Q4MnV0dHVRYkZoby9YR1NOVlQyeHMzLzNISURuakVld2QzelMyN1pxdytqSDdmaDZtMzZUMUYyd2lCeTRzUmYwQ1B6UTFmcXN3aXFISDJJNFJnMVMxWGZSMTJONTViWkNGdnBNOXZxYzB0SUZTdktCbTdhYUtCOHN6SmhYelB6bEVSVE9qaVdiakF1WElUMk0xeEJQK2xicW4va08xRWQ3bU9yMmc4a1NpWnZSZjRuMEpZQVhmMGdiKzlRdWRqN3RQRE1ya0ZTNlhveXA0UVZNZ3hVQnNTekxGN3ZxMmZYMjZkMzdwTk9RMHhDNDlMbGhURGFhYkRXZ1REOXQ4SFEvaGpQY2xhQjg3SEZzQUlCSmtqYWVjdHhQYmlueEtEbUVka1V4Mk5yb3pMZytKOEFJbzlqWEh5dTBjeWlMejRjcjNhcG4ycU1RRmpNa0hlTk5kNVl4OURJWGV0aUNRMjdCdWhxL3Vxam1kMStsTXM3Ym1qMzg3VUJNOEtPaDVPaSsrM0pwL0dVRVNVaGFCWmo1MWFlTUp2bGc4emdSQXROY2lBQnR4YjR2U1BPb0xoTHM0V3c4elJ4c252NXFWYW5NU2hxdCt0V1BTZ0xyVjcvQ2RaektFSUh3b2lTYnhmSmp2NlZkRUZxYmg4S05ucmpCcXQ1clMwVm5ObVFzdEV0d21qRWM3c1VFQUNyTWpIQStYZytSMlRRNjA0eFJpZ0JKMXdIMFNSa2NpNlVQbmx4UmZXdGgwWTZPQzgyazlDYXdLdjgzTThXQWxUVkJ5aXdFcWNOVCtRcmtSNkdlRFU4RGN1VThjbytqZ2s5QWNrcElVYTF6citWUG5NZnErRjJyZHpWT0NwM3ArdVdWUFRZZG9DdkU5NldYZThhMEVMVWtobDN3WFB1V0hoU01uMm9RUi9nNUIxUUo1UXhTcStxMytYWGRnYjVnR0NzRGs4VHVSK2ZIQllkaWFUdUJnMURLOG9hZlFZMWVrS0VYSnVwMndISkpLcUEwZFpnZ3ZXUXpyWlBCeExSeXAzQUJYSXBEbDQ3VHNQbU1pczJJdWVrNWtXS3F2Mng0eXhxWkpYQVRsMjl4ajJqZmtnemY4bE9vZmdWWEQ1UjFPcHlQQ09NdXdyTHBLZWdZdEttZnRTcE9zMjJoYkdONTM4WDgrS3pUS2UzekJKOGMxVmpHM2ZpeFhOUFYwdTBOQy9JTTF3N25CbWhQU05kT3JseEp5Q08zM2M2cERHMm5pdVhKRXgzNlFPOHlsbnNzVUJvclhqa2lLeEYvQnJ3b2hiaUZRTmZiaVpaK3kvSWQ2RVY1SXNsYWRoUUtWMllab0MvcW9BYkJrUmFCVCtOZkR0OHBWVnZwOUdab1lQb3ZaZ052b1F1UWI0bnRuRmVJWEl6YlRoSGo2bGVvYzdqVVAvSmdHcS9GU3liNUJDZ3JHamg0QXlTQ3FDR0dBSTFnSU1aajF6emdkamVNM2djVkJSVWFzQ2pielloWlZhaGgwQkhXQVY5M1AyQnIyMU1scUlRU3ZkZDJwTE9TcjZ6dGJnRWFheEFVUmhvUFBpQThUaHlNR0R4b0QyOVZMdlVxWnMzcXNHcHEwZzdtM1RRUEw5cDdCRG5BZTlod3VRa1o4WUdVYWlOaG1iZkFOa0IrTUp0dXN1a29YaDJ0WTRSMnZOVGUxUEN4ZDcrWGlWL3NSTjlWL3lYNUd4cUZWdzlIbCtMS1FqcnlSZnppdjR6NWMvSVoxU3l1ZzlTU2NTQVAzaDYrSGEzdkRKVnE1UVhrYmtlZmhuMFpIYTVKZWFndjRSdXlUd0NiNTJSWlQxbkZDWUNvTFlHdGJJZ25vd0pCVW1CanNEY0NWdnlvT3h5YkowUzVWVENGdlNTckJNT2w5N1FxbmZ5eE8xdlZ2SjVyQW1lOFhlRDRwNHQraGpnbmVqTVhDTWZFd2VXUmlnYzhsa1pQYVdZeGZSdGg5QkxzZnJIYlJkNVdGUWo5TExqRGtjNTMyWTJ1THNJd0dGamFySDFreTRmODNhMjkyYXAySm5RMnpQTFVXN29YQUpJbnRyOXpLMmhZend3dmVsYnIzN2JyNzlVSnE5U1ZNU1BVQUovNTc3bVIvT0pvNVJxMjFwcythODFieTArSVhJaHVEVmN2enlYVEVsUTc1VTFLKzZ6VUpGc1dtenhTSWJPaTBpRXZjUUlORWxwV2xhYVBXNzBuYW9RRUcyNWY5dDFRWFZzcDNqQTZsVHJwZTlnaExweG1QblBZQmxjR0F3NE9TQXUrKzdFeklDTHRIelBxOGZraFlESWlLUjQxMjIrQ2xGRmdMN29OSU92SkFIcFdQT0FMeFZ3Z3V4eVJkUWprTkROYmlxdW50Vlp2aHVsbGwvSnVCb1ltb0E5b00wUnBWR3ZlVDJrcXh3YTRaSm1RNVp4clluWjIrOEdzb0ZhT25ZeVdLYXk3aUhLTXVqMDZwTlRwMmNDaVFYVkk5a3BWZk13citha0VnSFVPbWhqR0FTRWpKbEJ3UTYxdmxEM3cxL0hZUUVHYWdhUExEQ1ZrdVpUa1lCN0NmcnpYL1cwYkdCRkkyR1ZKZ1dsRDE4Q0JhVEsxd2xEVEQ2Skx2akRHZkRyNXhMVzBXMG1TZ2p0ODFBOGZ2ZTFwalgrcEJndzJnTnBXWFNqaXNhc2N1WlpYQkZ6SG12ZDd4MW1uTU5IQTc5RFF1THV1cThQUmkzTVRyZFZUYmxlMmpwVUE2ek9GZ00wTDdzL0lzb01EOGYzTnV6MzRUb1o3QTJlRlBYMGpzYlNtRUtRaFRHaVlHY0FhN1g5RFZwaTdzbExzQXpWcExpUlg3UDlmYW8xVzY0ZW80WVY2dHJQa2pMVTU5eG9Ba25rNlRJU25oaE5YZlNyTkdPRGZwNmZxWmJscThZZlJ1c1Vmejd0MExYenlzTnJwdTVhN2RhVmM2TGMvZW1tYWZaaGh1R09lVVFiVHNUVkdxTVk4MDFoam1PN3k3bEVMcFRkZnpkQ0Y2NFFMb1BtR1RSeEl5eEVua2tnY1d3SkNNU3Njby9FWHV4aHBxSlpaMXJpRTZwUU1ZK2VFZElpT3djVFlMcXBMaWhwTFc2aW9RMlB4TTV4NWZ0OGpIdGMwbDJZTWhCT2VGSi9ZTE5JSXpiUzlTaUxqQnBWQnp2U1lxb3lVeUJHYUszeFpJeEJKcmNGSDFqcTFZdndjbGVSLzAxb2xIUHNjUkpVS2FzRWtSd24ycGZOYW0xMnBzeGNOaE0xTUhEaFh2cFM2YmpuMmpSSXkrUjlrVm9PcmhpelJYUXp3OXltaHhVRDhkbjNnVmJLRDhncTJvM0JJeG1kVlNJMFo2NTdobFI1OWlvU0lVemtRaHRiUko0YWhadEJKbTlsZDUrRSt6MU9CSVJudUo3ZUpiMTdSME1vRTZ5QjZlWmlVcm1TZWlpNFp1ZU1TbTIyUXczNjVPUC9tUTF4UWU0RUo1aEJueHhIcEhtNnZWZ2J2akNkSnQ4Z3d3Y1Iza0RGQmN0cVhkdXBjV2NKZ1Z5Nk5PYkRoSHRzeEdMQWZpTXMvcm5vb3R1b3pMeWZNUDlNaGVNS2xBeDY0ZW96SHdYSTZtZ3hqaHI2ZXRsNStnc3BwUDJzK1huT0E2Nlg0bDBHekNmbVVsaFZtY1ZGUStzUlYwekhqVWdRUmhPb2NIcUppR0xEU1NxdEdON1l0U1lWWkhORm93SWpyWWV4S0Npd05USG9iR2poU205NmMzdXYyTjZRU3MvWjVZYnJPR1dyVXZLc0FyMjlFdFZjZkJacnEvWEJKektjcWNMdXhWNVQ4MVBTSEl6UitvVzlGcjEycnhVY2xrb2puSTR0d252aFZaOWhCTnNvUCt1b1FLSEJDU1A1UjY5eG1nRjNpT25wdW5wWGY0UVNodWZGOE80RFlxY3pjTEhFRThXQXVEZHNnYmVNMTY1UVdIZTN2YjlMeE54SFhRVEEvWEczKzBVWU5KSDgxdUNyclgyRER3M055NTdzSE9oNnBhTU5aT0N4dDQ5VzFNTjNKNFYxeUtqOGJHeFVUbHVjVzFCZXJqVUxmRUZLRjBvdEZIUWcrbWRRYlR3SEViclJJcTZjMlhOU0pYK0JLait6VWI3SGk5WXlEaDZpY2dia1JwR0hlRkRlbEZOZm1NaUVlME1PUmlQazJUNWtRVlpCa0J2R216SjRzVkdyQy9pWmVseEFpR3lGUmlmaStVbG9wbHB4amNmVGZzelppYjRhOHVLQ3docDZTbmVxa25ZaW9OMUErSDZKcWQxQml3Wkp5N1dLYmlWN1U2NFpnRTJTeEI2Zk50dTlhdy9ueThMYTZ0dVhvY3A3ZUhRUGRqYXBKR2tGd204RXRaZHpaaDVRMlZ1WUcrUGc3UFZEeGxVS1l2M2Qyd2xXUFpUNkNDc1h5Vzg0ZjM2Z25xQnF2aFZsTlFJQlRXcXNwOGZMcnF1dTRvcFlOMVE5RVF5OTBIWFZmcHVMRUhndVRiNDRDaTRtLzVpbWpSOC9JWlUrSXpTTC9KQi9wOXBOYlVXUzBCdTJuSVFnRjJJaUZDTFpsWWhTQkUrNlNFZ29BL3V5NG5uQnByK0JjSG9WODFMU0l4MEwybXdKU1BXV0p2bnNRNGpVYkw4bVMySXFVZC9TOWpyT3ljNlB1Ti9kaTY4N3ZuTFFiUE5URUluSkw0RGFzcGxWZVQza0x1TEhnOWxzRFVCTzd2MzVCdzdONnRNMkttQkFlcUdKVXZjcWdVQWdrQng2Ykc1ZS9iNXVoSEJRZTRXZWhRTktRSjdnRitXUXVXMHQ3eUpaQ01wRnlvUHhWTEVFbUMxYk5pMUZVUXhnVG1QNVM2SkxQV3krSkUwdlVHRnNhY1l3cjNJVEM3YUVYVjVqek1ZQTExK2hBVXBvOXJKN2dQZCtDOHNPVG92YlpxWk11Qk85dXVkUFVndmFSRzBxUjhETDFCM3VjNjFEK1gyWisyZVdCTTZFUS84bnpna3JyVjNXV2NrTUc5cldPc09ISGUvVGtRTUFQN2lYaE1XRGNzbDRIbk1ud0FnaTlJejE5M3FTRTRyb1NGNnhBM3pJNm9sRm1SM3BXL2lNVGl1NTllMDZQOHlpMEhIZExqLzJTMWxLTmVyVG1GZHVmQWQwdURQbDdEcWRFdCswbFlNTmJvUER3NDNobjF0MmVOK2lhYkptZ2dTK054Z1NsdnpXWWlYR3Jtb0w4TGljdWU1WTlNcUlFdDg3alB5S2RZZTVNb1Rwak1DWHdmVlR1cVJKcDQzVGtDM3BKdUtQS1NYZkNFVlp3VlE3ekU4eXlEYnBLc280UTlyajM2OEtGbFE2ZWc4bWRTU1NYK2lQMmNSc1FlTDBYZ2F1MzQvMVhmWG5kTmtFalJKekhZV1M5ekJRYmVWbXAwU3hWQTBKdFphSGdpODQ5UkNiUXIzbEQzZnpPcUlKZXU1UG03dVoweW5NYVBHcUl6UTVJS1hXTGthUHoyb000c2wzalM3aktYTzZlY3llREJxa2pPeXc5UUZQZWoyOGx6Yi9PcGhXc3dHdHVyQk1PVXBWUSszZlVLY0hpdjdjeGx1NWhsQ2lxNHI2UitLNDBWL0t4ZTFoMG5iVDhnSnJBNDFXdXBhOHlQQ2J4U0tscXpseUpSZ1BHaHpWOG1XZVNLTU5Ic3h5a1VGbmowOTk4Z0ZEdVh4Z2RjSGFSSTFhRkt4YXRVMEhNM0plTE5lM1hRdDNQTmJGQUJyVnh6bUlkYkVwcUpEeldNSTJzek1jcmlMZCtXY2xOMDNHUFhiMmRoczJrZ1g1Mk9iRm1uZ0tTaUtrL0s5UnQ5NTM1MHBoWkJPc3k3ZU04T1I0NkxpTGUzQnRKT3VUdXZhRWtzV0dJSk1rK3luS1A4R1NhOENjY3lnYTNnUW5Zbm1TbXVkQVJBK1RuQ1JYRUhxQmFLaXJYNjNYMUVLZG9pVjEwV2dEVlA0S3pxVWs0T0IyMUhsU0dUMkZ2MzIrWnY2Y2dNUHpCaFdxWU4rMTNKdnFXQVMydXVCRDZjTXNnUVVGYzg3ZUxvN3I1bWo3ZWVjTkhsKzk0NnBTZDNkNDFXNUNsemZQajlnemhmcmtGYWxKb3dKSUpKa3lXTndCQUZFQjdVaStBQm9OZHliU0FHSERiQk0vYzFDUCtMNlpZS29kNzk2WUY3QTZnajloc2tsL0dIVVFqckV3Ynhka1lOQVdxNEdXU1JUY04zT2pRcEt3ZThRcFVHZWQ0ckd2c1k2MWlzaWJSeHBtZ1E2ejZKdm1WRWM3SUlFSTNHM2FvRmhpNCtraGZFSkhweVh3ZFB5OENTVURPM3g3ZnVDTFdjRzNpOTVXcDU1RmRHRHZha2c0dGh6WGFVcCtveVFjUTRHMTB6ZzRBMnQ5SEZ2WlV3dWhSbjh3Y2phVWM2b3F4R04zakpRbmU3MGdJTWtwUitPYmc4RklNdHcyWHlyQm1hUWllQnUxcy9OWGxaalg2ZnI5aStGb25Sc3g3eGo5RndEVVBlKzJLcDQwZ0JuMEZUUVJmMW5VaSs1Nkk2VnN0aU1yNjFuRXE0RUJERS9mQmVDZlZnWXl6eEFmZ0JPWFBPYUI5MmQxTEEyU0g4T1BVWEtkOFdYUVlFb0Z1VXRaWmNUMnVrSnAyaE5mR3lhenlHSzJoblhkSHg4U05ocmZ0MzZEcjB4d0FneG5JUzM2UW5ubDFMZG1QYUdrcVVlTjdnU1dnOGRSd29YV253cnN5dkdqSUlQQ2FKOVh6TEczYks4Y0dsRWFqMnVQNEoyMGR1TE4weFd2STNKc0hTTUdzMTF2aC9lemoveWdhSjA4U0wzaVZwNUdFUHpYNXhNWHoyTTAvL0R0a3NqU3EyZ2R0SXByYnlvVk9OSmxJZUx0NFprdnVEcGxSc0NyazNOWHRDSnI4UGhSSXVGK29XdE0vQmRnTkV5c05iaGZXUjdQbnRnTlN6VTBnMEYwWFNlZ1ZsQTBNaVhYbHY1K3dwTmovU1FXVFVKSlZucDhVZ25yY2J0V1NMSW9adSt3dUZUWXE2bmRJaDdjSGsrRmNnQkVxVlJMTXViR1FDckxZalZrVjdFRmpmSUd1WHpaTmlESGFhKzFRVWd5SnAzaG5YN0xvdHg3dGFTNm9QekN0QlJucVBmVFJzWnZjUjJvN1FmOVBvbkorWkJWck5DNUdzZHNrb0lyZkdKZUE4czRTN21OLzhhSFlBVjQrWkxuZEFEdXAwMDhFSFZLaEE0VGxPRitzMlRYOUR0TmNYbWxBdkc4REVsM0t3d0RRaFVpREFTaWZPY1RZRzBwYU4wczl3bVBTSi9WTGZKa1RublV2MFJIN2Jsb1lkVG83WjUxWUR0bWVRY3JxVGhjd3M0cTdCVHk1UkdPSytNMEx5bmNneHduRVRyby8wWDVYWEtEa1pPU1crdU1DSkwyTVZtcHZrRUNHcVcwbmdaUlBUMUlZODV1ZzNrd0FPOGExNXJTWnp0aE8xKzFFdy8rNzJQcDk0d0NCT1c4bHJRb05JekF3RWhLNXBXZTlGcUhFOHZrNVpPcFd1REsrUm8rS2prSTBvWHlpTjhORjVyVUxndjllb1FJNjBGN09TZFl1OWdIQ0cwTE50Z0sxTWpScWpaaVhKZWExS3R6NXlnNWhWOTd4d3FtTmhKQ2JoVEh6YW5iSnlDQjkwRjgwYUNDVzJYQkJYVXFadDB3dUtjQ0xEa2U2RFNvWUl6cFBjYVdYYktjcnB6em1xRXhYNzV2aFFHUWVidFczYy9Rdi9iSXlDR0puRzB0TW1Zczh6bzRva2VxNDc5NFBIR2RGQVc3alJDU1pPT3M2MUlJcnVhMk43VktpRThULzFoSnphUHBRSkY5dzVVWEZzME9YVE9UQ09qNGhSc1A0czMxcGhCVTZtOGFETmd2QnZML2cwdXN5eG5nUEtPRVlnT1BObzRDeWVCUk09IiwiaXYiOiJhMzdmYzJkNTA4ZTg5MzdlMTc4N2QwMWYzOTcxZjgzYSIsInMiOiI5YTkzMzA2OWQyNjRhYTBlIn0=',
                
                'public_key': key,
                'site': 'https://iframe.arkoselabs.com',
                'userbrowser': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
                #'capi_version': '10.2.0',
                'capi_version': '1.4.0',
                'capi_mode': 'inline',
                'style_theme': 'default',
                #'language': '',
                'rnd': f'0.{rand_string}',
                'data[blob]': 'undefined'
                }
                
                
                r=s.post(f'https://client-api.arkoselabs.com/fc/gt2/public_key/{key}',data=pay,headers=head,proxies=proxy)
                #print(r.text)
                session=r.json()['token']
                
                sest=session.split('|')[0]
                #print(sest)
                sid=session.split('r=')[1].split('|')[0]
                #print(sid)

                                    #https://client-api.arkoselabs.com/fc/assets/ec-game-core/game-core/1.10.0/standard/index.html?session=&theme=default
                head['Referer']=f'https://client-api.arkoselabs.com/fc/assets/ec-game-core/game-core/1.10.0/standard/index.html?session={session}&theme=default'
                

                if True:
                    r=s.get(f'https://client-api.arkoselabs.com/fc/gc/?token={session.split("|")[0]}',headers=head,proxies=proxy)
                    #print(r.text)




                    pay={
                        'sid': sid,
                        'session_token': sest,
                        'analytics_tier': 40,
                        'render_type': 'canvas',
                        'category': 'Site URL',
                        'action': #'https://client-api.arkoselabs.com/v2/{key}/enforcement.ce1f6993d53717e81d8903f8716dc9ed.html'
                        'https://client-api.arkoselabs.com/v2/{key}/enforcement.b1233413be3c6f4c7c53bf9beaf64fa7.html'
                        }

                    r=s.post(f'https://client-api.arkoselabs.com/fc/a/',headers=head,data=pay,proxies=proxy)
                    #print(r.text)
                    



                    
                    # r=s.get('https://client-api.arkoselabs.com/cdn/fc/assets/style-manager/styles/dc2833dc-6a20-4f4d-b56b-7de82dc901ee.css',proxies=proxy)
                    # print(r)



                    pay={'token': sest,
                    'sid': sid,
                    'render_type': 'canvas',
                    'lang': '',
                    #'en',
                    'isAudioGame': 'false',
                    'analytics_tier': '40',
                    'apiBreakerVersion': 'blue'


                            }

                    r=s.post(f'https://client-api.arkoselabs.com/fc/gfct/',headers=head,proxies=proxy,data=pay)

                    cha_id=r.json()['challengeID']
                    
                    images=r.json()['game_data']['customGUI']['_challenge_imgs']
                    #print(len(images))


                    typ=r.json()['game_data']['gameType']

                    for op in r.json()['string_table']:
                        if 'instructions-' in op and 'Microsoft' not in op and op[1]=='.':
                            zadanie=r.json()['string_table'][op]
                    
                    waves=r.json()['game_data']['waves']
                    variks=r.json()['game_data']['game_difficulty']

                    if waves<=guru_l and variks<=10:

                        pay={
                            'sid': sid,
                            'session_token': sest,
                            'game_token': cha_id,
                            'analytics_tier': '40',
                            'render_type': 'canvas',
                            'category': 'loaded',
                            'action': 'game loaded'
                            }

                        r=s.post(f'https://client-api.arkoselabs.com/fc/a/',headers=head,data=pay,proxies=proxy)
                        #print(r.text)



                        pay={
                            'sid': sid,
                            'session_token': sest,
                            'game_token': cha_id,
                            'analytics_tier': '40',
                            'render_type': 'canvas',
                            'category': 'begin app',
                            'action': 'user clicked verify'
                            }

                        r=s.post(f'https://client-api.arkoselabs.com/fc/a/',headers=head,data=pay,proxies=proxy)
                        #print(r.text)

                        pay={
                            'sid': sid,
                            'session_token': sest,
                            'game_token': cha_id,
                            }

                        r=s.post('https://client-api.arkoselabs.com/fc/ekey/',headers=head,data=pay,proxies=proxy)
                        try:
                            metadata=update_metadata(origin="ekey",metadata=metadata)
                            decr=r.json()['decryption_key']
                        except:
                            metadata={}
                            decr=sest

                        w=1
                        gss=[]
                        zadanie=zadanie.split('(')[0].split('.')[0].replace('<strong>','').replace('</strong>','').replace('<b>','').replace('</b>','').strip()
                        print(zadanie)
                        

                        for imga in images:
                            
                            r=s.get(imga, stream=True)
                            try:
                                img_data=cryptojs_decrypt(
                                r.text,decr )

                                #print(img_data)
                                if False:
                                    with open(f"D:\\Python_scripts\\UNIQUE\\captcha\\images\\imageToSave{w}.png", "wb") as fh:
                                        fh.write(base64.decodebytes(img_data))
                                else:
                                    #with open(f"D:\\Python_scripts\\UNIQUE\\captcha\\images\\imageToSave{w}.png", "wb") as fh:
                                        #fh.write(base64.decodebytes(img_data))

                                    ee = base64.b64encode(base64.decodebytes(img_data))
                            except:
                                
                                if False:
                                    with open(f"D:\\Python_scripts\\UNIQUE\\captcha\\images\\imageToSave{w}.png", 'wb') as f:
                                        for chunk in r:
                                            f.write(chunk)
                                else:
                                    
                                   # with open(f"D:\\Python_scripts\\UNIQUE\\captcha\\images\\imageToSave{w}.png", 'wb') as f:
                                        #for chunk in r:
                                            #f.write(chunk)

                                    ee=base64.b64encode((r.content))

                            #print(ee)

                            payload = {'textinstructions': zadanie, 'click': 'funcap2', 'key': 'dff6de39f8be13e6749f7cdb869fcd4f', 
                                    'method': 'base64'
                                    , 'body': ee
                                    }

                            r = requests.post("http://api.captcha.guru/in.php", data=payload#,files=filed
                            )
                            print(r.text)

                            rt = r.text.split('|')
                            url = 'http://api.captcha.guru/res.php?key='+'dff6de39f8be13e6749f7cdb869fcd4f'+'&id='+rt[1]
                            # action = webdriver.ActionChains(driver)
                            # for i in range(2):
                            #     try:
                            #         action.move_by_offset(random.randint(-20,20),random.randint(-20,20))
                            #         action.perform()
                            #         time.sleep(1)
                            #     except:
                            #         pass

                            while True:
                                response = requests.get(url).text
                                if 'ERROR' in response:
                                    raise Exception(response)
                                if '|' in response:
                                    break
                            #times.sleep(random.randint(5,8))                    
                            #answer=input("? - ")
                            answer=int(response.split('|')[-1])-1

                            if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
                                gss.append({'index':int(answer)})

                            

                            elif key=='B7D8911C-5CC8-A9A3-35B0-554ACEE604DA':
                                
                                gss.append({"guess":int(answer)})

                                #                     api_breaker
                                # : 
                                # {key: "kc", value: ["vc", "vc", "vb"]}
                                # key
                                # : 
                                # "kc"
                                # value
                                # : 
                                # ["vc", "vc", "vb"]
                                # 0
                                # : 
                                # "vc"
                                # 1
                                # : 
                                # "vc"
                                # 2
                                # : 
                                # "vb"
                            elif False:
                                gss.append([int(answer)])


                                #                     api_breaker
                                # : 
                                # {key: "kb", value: ["vc", "vc"]}
                                # key
                                # : 
                                # "kb"
                                # value
                                # : 
                                # ["vc", "vc"]
                                # 0
                                # : 
                                # "vc"
                                # 1
                                # : 
                                # "vc"


                            elif key=='0152B4EB-D2DC-460A-89A1-629838B529C9':
                            # "[{"px":"0.52","py":"0.85","x":157.09375,"y":171}]"
                                
                                
                                gss.append({"px":"0.52","py":"0.85","x":157.09375,"y":171})

                            g=json.dumps(gss)#.replace(' ','')
                            
                            #print(f'key = {sest}')
                            print(g)

                            #guess=json.loads(cryptojs_encrypt(g,sest))
                            guess=cryptojs_encrypt(g,sest)
                            print(guess)

                            time = str(int(times.time() * 1000))

                            # Manipulate timestamp string
                            value = time[:7] + '00' + time[7:13]
                            #head['Cookie']=f'timestamp={value};path=/;secure;samesite=none'
                            head['Cookie']=f'timestamp={value}'
                            head['X-Newrelic-Timestamp']= value
                            if w==waves:
                                
                                #update_metadata(origin="lastguess",metadata=metadata, key=key, value=gss[-1])
                                metadata=update_metadata(origin="guess",metadata=metadata)
                            else:
                                
                                metadata=update_metadata(origin="guess",metadata=metadata)
                            xr=get_request_id(sest,metadata)
                            print(metadata)

                            head["X-Requested-ID"]= xr

                            pay={
                                'session_token': sest,
                                'game_token': cha_id,
                                'sid':sid,
                                'guess': guess,
                                'render_type': 'canvas',
                                'analytics_tier': '40',
                                
                                
                            }
                            if False:
                                while True:
                                    mbio=''
                                    crt=0
                                    cx=random.randint(1,600)
                                    cy=random.randint(1,600)
                                    #474,254
                                    acts=random.randint(90,200)

                                    dacts=[]
                                    for jopa in range(answer):
                                        dacts.append(random.randint(1,acts))
                                    
                                    ccc=0
                                    for movik in range(acts):
                                        if random.randint(1,10)>5 or ccc in dacts:
                                            crt+=random.randint(1,100)
                                            while True:
                                                nx=cx+random.randint(-10,10)
                                                if nx>0 and nx<600:
                                                    cx=nx
                                                    break

                                            while True:
                                                ny=cy+random.randint(-10,10)
                                                if ny>0 and ny<600:
                                                    cy=ny
                                                    break

                                            if ccc in dacts:
                                                tac=1
                                                cx=475+random.randint(-5,5)
                                                cy=250+random.randint(-5,5)
                                            else:
                                                tac=0        
                                                
                                            mbio+=f'{crt},{tac},{cx},{cy};'
                                        ccc+=1
                                    if len(mbio.split(';'))>50:
                                        break
                                bio={"mbio":mbio,"tbio":"","kbio":""}
                            else:
                                
                                bio="35815,0,216,331;35817,1,216,331;35819,2,216,331;39143,0,265,244;39144,1,265,244;39145,2,265,244;39329,0,265,244;39330,1,265,244;39331,2,265,244;39508,0,265,244;39508,1,265,244;39509,2,265,244;39700,0,265,244;39701,1,265,244;39701,2,265,244;39884,0,265,244;39884,1,265,244;39885,2,265,244;40068,0,150,311;40070,1,150,311;40071,2,150,311;"

                                while True:
                                    if len(bio.split(',1,'))==answer+3:
                                        break
                                    else:
                                        bio=bio.replace(',1,',',0,',1)
                            #print(mbio)
                            
                            
                                bio={"mbio":bio,"tbio":"","kbio":""}
                            #print(bio)
                            bio=base64.b64encode(json.dumps(bio).encode()).decode()
                            #print(bio)
                            #pay['bio']='eyJtYmlvIjoiMTI1MCwwLDE0NywyMDQ7MTg5NCwwLDE1MSwyMDA7MTk2MCwxLDE1MiwxOTk7MjAyOSwyLDE1MiwxOTk7MjU3NSwwLDE1NSwxOTU7MjU4NSwwLDE1NiwxOTA7MjU5NSwwLDE1OCwxODU7MjYwNCwwLDE1OSwxODA7MjYxMywwLDE2MCwxNzU7MjYyMSwwLDE2MSwxNzA7MjYzMCwwLDE2MywxNjU7MjY0MCwwLDE2NCwxNjA7MjY1MCwwLDE2NSwxNTU7MjY2NCwwLDE2NiwxNTA7MjY3NywwLDE2NiwxNDQ7MjY5NCwwLDE2NywxMzk7MjcyMCwwLDE2NywxMzM7Mjc1NCwwLDE2NywxMjc7Mjc4MywwLDE2NywxMjE7MjgxMiwwLDE2NywxMTU7Mjg0MywwLDE2NywxMDk7Mjg2MywwLDE2NywxMDM7Mjg3NSwwLDE2Niw5ODsyOTA1LDAsMTY1LDkzOzMyMzIsMCwxNjUsOTk7MzI2MiwwLDE2NSwxMDU7MzI5OSwwLDE2NCwxMTA7MzM0MCwwLDE2MSwxMTU7MzM3MiwwLDE1NywxMjA7MzM5NSwwLDE1MywxMjQ7MzQwOCwwLDE0OCwxMjc7MzQyMCwwLDE0MywxMzA7MzQyOSwwLDEzOCwxMzE7MzQ0MSwwLDEzMywxMzQ7MzQ1MCwwLDEyOCwxMzU7MzQ2MSwwLDEyMywxMzg7MzQ3NiwwLDExOCwxNDA7MzQ4OSwwLDExMywxNDI7MzUwMywwLDEwOCwxNDM7MzUxOCwwLDEwMywxNDQ7MzUzNCwwLDk4LDE0NTszNTU2LDAsOTMsMTQ2OzM2MTUsMCw4OCwxNDg7MzY2MiwwLDgzLDE1MTszNjgzLDAsNzgsMTU0OzM3MDEsMCw3MywxNTc7MzcyNSwwLDY5LDE2MTszNzkzLDEsNjgsMTYyOzM4NTEsMiw2OCwxNjI7IiwidGJpbyI6IiIsImtiaW8iOiIifQ=='
                            pay['bio']=bio

                            #'eyJtYmlvIjoiMTQsMCw0NzcsMzM3OzI3LDAsNDc2LDMzNzszNywwLDQ3NSwzMzg7NDUsMCw0NzQsMzM4OzUyLDAsNDczLDMzODs2MCwwLDQ3MiwzMzg7NjEsMCw0NzIsMzM5OzY3LDAsNDcxLDMzOTs3NCwwLDQ3MCwzMzk7ODQsMCw0NjksMzM5OzkzLDAsNDY5LDM0MDs5MywwLDQ2OCwzNDA7MTAxLDAsNDY3LDM0MDsxMTAsMCw0NjYsMzQwOzEyMCwwLDQ2NSwzNDA7MTIyLDAsNDY1LDM0MTsxMjksMCw0NjQsMzQxOzEzNiwwLDQ2MywzNDE7MTQ0LDAsNDYyLDM0MTsxNTAsMCw0NjEsMzQxOzE1MiwwLDQ2MSwzNDI7MTU3LDAsNDYwLDM0MjsxNjMsMCw0NTksMzQyOzE3MCwwLDQ1OCwzNDI7MTc2LDAsNDU3LDM0MjsxODEsMCw0NTcsMzQzOzE4MSwwLDQ1NiwzNDM7MTg4LDAsNDU1LDM0MzsxOTUsMCw0NTQsMzQzOzIwMiwwLDQ1MywzNDM7MjA4LDAsNDUyLDM0MzsyMTUsMCw0NTEsMzQzOzIyMywwLDQ1MCwzNDM7MjMzLDAsNDQ5LDM0NDsyNDEsMCw0NDgsMzQ0OzI1MCwwLDQ0NywzNDQ7MjYwLDAsNDQ2LDM0NDsyNzQsMCw0NDUsMzQ0OzYwOSwwLDQ0NSwzNDM7NjEwLDAsNDQ1LDM0Mjs2MTMsMCw0NDUsMzQxOzYxNCwwLDQ0NiwzNDA7NjE2LDAsNDQ2LDMzOTs2MTgsMCw0NDYsMzM4OzYyMCwwLDQ0NywzMzc7NjIxLDAsNDQ3LDMzNjs2MjMsMCw0NDcsMzM1OzYyNSwwLDQ0NywzMzQ7NjI2LDAsNDQ4LDMzMzs2MzAsMCw0NDgsMzMyOzYzMCwwLDQ0OCwzMzE7NjMyLDAsNDQ5LDMzMDs2MzMsMCw0NDksMzI5OzYzNSwwLDQ0OSwzMjg7NjM4LDAsNDUwLDMyNzs2MzksMCw0NTAsMzI2OzY0MCwwLDQ1MCwzMjU7NjQyLDAsNDUwLDMyNDs2NDQsMCw0NTEsMzIzOzY0NywwLDQ1MSwzMjI7NjQ4LDAsNDUxLDMyMTs2NTAsMCw0NTIsMzIwOzY1MywwLDQ1MiwzMTk7NjU2LDAsNDUyLDMxODs2NTcsMCw0NTMsMzE3OzY1OSwwLDQ1MywzMTY7NjU5LDAsNDUzLDMxNTs2NjIsMCw0NTMsMzE0OzY2MywwLDQ1NCwzMTM7NjY4LDAsNDU1LDMxMDs2NzQsMCw0NTYsMzA4OzY3NCwwLDQ1NiwzMDc7Njc2LDAsNDU2LDMwNjs2NzcsMCw0NTcsMzA1OzY4MCwwLDQ1NywzMDQ7NjgyLDAsNDU4LDMwMzs2ODIsMCw0NTgsMzAyOzY4NCwwLDQ1OCwzMDE7Njg1LDAsNDU5LDMwMTs2ODYsMCw0NTksMzAwOzY4OSwwLDQ2MCwyOTk7NjkwLDAsNDYwLDI5ODs2OTEsMCw0NjAsMjk3OzY5MywwLDQ2MSwyOTY7Njk1LDAsNDYxLDI5NTs2OTcsMCw0NjIsMjk0OzY5OSwwLDQ2MiwyOTM7NzAxLDAsNDYzLDI5Mjs3MDIsMCw0NjMsMjkxOzcwNSwwLDQ2MywyOTA7NzA2LDAsNDY0LDI4OTs3MDgsMCw0NjQsMjg4OzcxMCwwLDQ2NSwyODc7NzExLDAsNDY1LDI4Njs3MTQsMCw0NjUsMjg1OzcxNCwwLDQ2NiwyODU7NzE1LDAsNDY2LDI4NDs3MTcsMCw0NjYsMjgzOzcxOSwwLDQ2NywyODI7NzIwLDAsNDY3LDI4MTs3MjIsMCw0NjcsMjgwOzcyNCwwLDQ2OCwyNzk7NzI1LDAsNDY4LDI3ODs3MjcsMCw0NjgsMjc3OzczMCwwLDQ2OSwyNzY7NzMxLDAsNDY5LDI3NTs3MzIsMCw0NjksMjc0OzczNCwwLDQ3MCwyNzM7NzM2LDAsNDcwLDI3Mjs3MzgsMCw0NzAsMjcxOzc0MCwwLDQ3MSwyNzA7NzQxLDAsNDcxLDI2OTs3NDMsMCw0NzEsMjY4Ozc2MSwwLDQ3MiwyNjI7NzYzLDAsNDcyLDI2MTs3NjcsMCw0NzIsMjYwOzc3MSwwLDQ3MiwyNTk7Nzc2LDAsNDcyLDI1ODs3ODMsMCw0NzIsMjU3Ozc4OCwwLDQ3MiwyNTY7NzkzLDAsNDcxLDI1NTs3OTksMCw0NzEsMjU0OzgwNSwwLDQ3MCwyNTM7ODExLDAsNDY5LDI1Mjs4MTksMCw0NjgsMjUxOzgyNSwwLDQ2NywyNTE7ODI3LDAsNDY3LDI1MDs4MzAsMCw0NjYsMjUwOzgzNiwwLDQ2NSwyNTA7ODQyLDAsNDY0LDI1MDs4NDUsMCw0NjQsMjQ5Ozg0OCwwLDQ2MywyNDk7ODU4LDAsNDYyLDI0OTsxMTU5LDAsNDYxLDI0OTsxMTc0LDAsNDYwLDI0OTsxMTg4LDAsNDU5LDI0OTsxMTkwLDAsNDU5LDI0ODsxMjE3LDAsNDU4LDI0ODsxMjQwLDAsNDU3LDI0ODsxMjU5LDAsNDU2LDI0ODsxMjk5LDAsNDU1LDI0ODsxMzU3LDAsNDU0LDI0ODsxNDUxLDAsNDUzLDI0ODsxNjAwLDAsNDU0LDI0ODsxNjE2LDEsNDU0LDI0ODsxNjIyLDAsNDU1LDI0ODsxNjg4LDIsNDU1LDI0ODsxNjk2LDAsNDU1LDI0ODsxNzA5LDAsNDU1LDI0OTsxNzEwLDAsNDU1LDI1MDsiLCJ0YmlvIjoiIiwia2JpbyI6IiJ9'
                            #print(pay)
                            #print()
                            #print(head)
                            
                            r=s.post('https://client-api.arkoselabs.com/fc/ca/',headers=head,data=pay,proxies=proxy)
                            print(r.text)

                            try:
                                decr=r.json()['decryption_key']
                            except:
                                pass

                            w+=1

                        
                        if r.json()['solved']==True:
                            print(session)
                            break

                        #wrk#267175667c150ebb6.8179552405|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|rid=42|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                            #933175669dc739d04.7834423605|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                        else:
                            # global fer
                            # fer+=1
                            pass
                    else:
                        print('too much')
                        print(waves,variks)
                        r=requests.get('https://mobileproxy.space/reload.html?proxy_key=66094b6809fcdea08e2a6525eb111d4a?format=json',headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36',}).text
                        print(r)
                
            except Exception as zxc:
                print(repr(zxc))
            finally:
                try:
                    s.close()
                except:
                    pass




gurud=0
def guru_token(key,proxystr,pid,ua):
    global fer
    global gurud
    gurud+=1
    #proxystr='185.130.226.44:11982'
    #proxystr=None
    #43517554a9a7fa469.1878053805&r=eu-west-1&meta=7&meta_height=325&metabgclr=%23ffffff&metaiconclr=%23757575&mainbgclr=%23ffffff&maintxtclr=%231B1B1B&guitextcolor=%23747474&lang=en&pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA&at=40&ht=1&ag=101&cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc&lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com&surl=https%3A%2F%2Fclient-api.arkoselabs.com&smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
    #612175549c84eff01.8694108105|r=eu-west-1|meta=7|meta_height=325|metabgclr=%23ffffff|metaiconclr=%23757575|mainbgclr=%23ffffff|maintxtclr=%231B1B1B|guitextcolor=%23747474|lang=en|pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA|at=40|ht=1|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
    if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
        site='https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html?theme=default'
        guru_l=5

    elif key=='B7D8911C-5CC8-A9A3-35B0-554ACEE604DA':
        site='https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html?mkt=en'
        guru_l=5

    

    try:
        
        zzz=1
        while True:
            zzz+=1
            if True:
                try:
                    driver.quit()
                    if pid:
                        changecr()
                except:
                    pass

                try:
                    os.remove(f'{asd}.zip')
                except:
                    pass

                asd=str(random.randint(-9999999,9999999))

                dr=selenium_driver_gen.sel_driver_gen()
                driver,proxdict,ua =dr.gen(asd,proxystr#,userAgent=ua
                )
               # print(driver.session_id,ua)

            else:
                if zzz%3==0:
                    try:
                        driver.quit()
                    except:
                        pass
                    time.sleep(randim.randint(2,5))
                    dr=selenium_driver_gen.sel_driver_gen()
                    driver,proxdict,ua =dr.gen(asd,proxystr#,userAgent=ua
                    )
                    print(driver.session_id)

            driver.set_window_size(randint(800,1700), randint(500,1100))
            driver.get(site)
            #input('??')
            
            try:
                #wait load and swith to frame#
                WebDriverWait(driver, 15).until(EC.frame_to_be_available_and_switch_to_it((By.XPATH,'//*[@id="arkose"]/div/iframe')))
                
                WebDriverWait(driver, 15).until(EC.frame_to_be_available_and_switch_to_it((By.ID,'game-core-frame')))

                resp=dr.network2(driver,'standard/index.html?')
                
                token=resp[0]['params']['request']['url']
                token='|'.join(token.split('session=')[-1].split('&')[:-1])
                #click start#
                WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="root"]/div/div[1]/button'))).click()

                
                zadanie=WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.XPATH,'//*[@role="text"]'))).text
                variks=WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/div/div/div[2]/div[2]'))).get_attribute('aria-label')
                variks= int(variks.split(' ')[-1])
                kolvo=int(zadanie.split(' ')[-1].split(')')[0])
                driver.switch_to.default_content()
                #if kolvo<=guru_l and variks<=10:
                if True:
                    s=requests.session()
        
                    retry = Retry(connect=3, backoff_factor=0.5)
                    adapter = HTTPAdapter(max_retries=retry)
                    #adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,max_retries=retry)
                    s.mount('http://', adapter)
                    s.mount('https://', adapter)
                    s.headers={'Connection': 'close'}
                    
                    
                    key = 'dff6de39f8be13e6749f7cdb869fcd4f'
                    
                    try:
                        driver.switch_to.window(driver.window_handles[1])
                    except:
                        driver.execute_script("window.open('');")

                    driver.switch_to.window(driver.window_handles[0])
                    img_url=''
                    for i in range(kolvo):
                        
                        resp=[]
                        zzz2=time.time()
                        while True:
                            
                            resp=dr.network2(driver,'blob:https://client-api.arkoselabs.com/')
                            #print(len(resp))
                            if len(resp)!=0:
                                img_url2=resp[0]['params']['request']['url']
                                if img_url2!=img_url:
                                    break

                            if time.time()>=zzz2+15:
                                raise Exception('zzz2 error ahuet')
                            #time.sleep(0.1)

                        driver.switch_to.window(driver.window_handles[1])
                        img_url=resp[0]['params']['request']['url']
                        #print(img_url)
                        driver.get(img_url)
                        
                        
                        
                        with open(f'captcha_im/{asd}.png', 'wb') as file:
                            l=WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH,'/html/body/img')))
                            #l=driver.find_element_by_xpath('/html/body/img')
                            file.write(l.screenshot_as_png)
                        
                        
                        img = Image.open(f'captcha_im/{asd}.png')


                        img = img.resize((variks*200,400), Image.Resampling.LANCZOS)
                        img.save(f'captcha_im/{asd}.png')


                        im = Image.open(f'captcha_im/{asd}.png')
                        rgb_im = im.convert('RGB')
                        rgb_im.save(f'captcha_im/{asd}.jpg')

                        with open(f'captcha_im/{asd}.jpg', "rb") as image_file:
                            ee = base64.b64encode(image_file.read())
                        

                        driver.switch_to.window(driver.window_handles[0])


                        

                        
                        zadanie=zadanie.split('(')[0].split('.')[0].strip()

                        #filed = {'file': image_file}
                        if False:#guru
                            payload = {'textinstructions': zadanie.split('(')[0].split('.')[0].strip(), 'click': 'funcap2', 'key': key, 
                            'method': 'base64'
                            , 'body': ee
                            }
                            
                            

                            if True:
                                apa='api.captcha.guru'
                                kkk='dff6de39f8be13e6749f7cdb869fcd4f'
                            else:
                                apa='goodxevilpay.shop'
                                kkk='p0zQFrFTZ17uDmsH8x0LzN2bjyT8pHYG'

                            #print(apa)    
                            payload = {'textinstructions': zadanie , 'click': 'funcap2'
                            , 'key': kkk, 
                                    'method': 'base64'
                                    , 'body': ee
                                    }
                            r = requests.post(f"http://{apa}/in.php", data=payload#,files=filed
                            )
                            #print(r.text)

                            rt = r.text.split('|')
                            url = f'http://{apa}/res.php?key='+kkk+'&id='+rt[1]
                        else:#xevil
                            if zadanie=='Use the arrows to rotate the animal with the same icon to face where the hand is pointing':
                                zadanie='Use the arrows to rotate the animal to face in the direction of the hand'
                                    
                           #print(zadanie)  

                            data = {'key': 'p0zQFrFTZ17uDmsH8x0LzN2bjyT8pHYG','method':'post','imginstructions':zadanie,
                            'recaptcha':1
                            #'textinstructions':zadanie
                            } 

                            mgm=open(f'captcha_im/{asd}.jpg', 'rb')

                            file = {'file':  mgm}

                            r = requests.post('http://83.220.173.239:20875/in.php', data=data, files=file
                            ) #ERROR_CAPTCHA_UNSOLVABLE

                            mgm.close()

                            if '|' in r.text:
                                ref = r.text.split('|')[-1]
                                
                                url = f'http://83.220.173.239:20875/res.php?key=p0zQFrFTZ17uDmsH8x0LzN2bjyT8pHYG&action=get&id={ref}'

                            else:
                                # try:
                                #     with open(f"{pathik}\\{sest}{random.randint(1,999)}{w}.png", "wb") as fh:
                                #         fh.write(base64.decodebytes(img_data))
                                # except:
                                #     with open(f"{pathik}\\{sest}{random.randint(1,999)}{w}.png", 'wb') as f:
                                #         for chunk in rim:
                                #             f.write(chunk)
                                raise Exception(r.text)

                        while True:
                            response = requests.get(url).text
                            if 'ERROR' in response:
                                #print(ee)
                                print(zadanie)
                                try:
                                    os.mkdir(f'captcha_im/{zadanie}')
                                except:
                                    pass
                                try:
                                    os.replace(f'captcha_im/{asd}.jpg', f'captcha_im/{zadanie}/{asd}.jpg')
                                except:                                    
                                    pass

                                try:
                                    os.replace(f'captcha_im/{asd}.png', f'captcha_im/{zadanie}/{asd}.png')
                                except:                                    
                                    pass

                                raise Exception(response)

                            if '|' in response:
                                try:
                                    os.remove(f'captcha_im/{asd}.png')
                                except:
                                    pass
                                try:
                                    os.remove(f'captcha_im/{asd}.jpg')
                                except:
                                    pass
                                
                                break
                            


                        #https://blob:client-api.arkoselabs.com/821c0e28-b11b-47eb-94c7-4b2a10d541e0
                        WebDriverWait(driver, 15).until(EC.frame_to_be_available_and_switch_to_it((By.XPATH,'//*[@id="arkose"]/div/iframe')))
                
                        WebDriverWait(driver, 15).until(EC.frame_to_be_available_and_switch_to_it((By.ID,'game-core-frame')))
                        
                        # action = webdriver.ActionChains(driver)
                        # element =WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/div/div/div[2]/div[1]/a[2]')))
                        # action.move_to_element(element)
                        # action.perform()




                        for cl in range(int(response.split('|')[-1])-1):
                            
                            WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/div/div/div[2]/div[1]/a[2]'))).click()
                            #time.sleep(0.01)

                        
                        # action = webdriver.ActionChains(driver)
                        # element=WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/div/button')))
                        # action.move_to_element(element)
                        # action.perform()
  
                        WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/div/button'))).click()
                        
                        
                    
                    try:
                        dt=WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.XPATH,'//*[@id="root"]/div/div[1]/h2'))).get_attribute('data-theme')
                        if 'victory' in dt:
                            print("EBATT",kolvo)
                            #time.sleep(1)
                            er=False
                            break
                    except Exception as x:
                        fer+=1
                        print(repr(x),'result',kolvo)
                        
                        


                else:
                    raise Exception('too much')

            except Exception as x:
                try:
                    driver.quit()
                except:
                    pass
                print(repr(x))
                # if pid:
                #     changecr(pid)
                  
            
    except Exception as x:
        er=True
        print(repr(x))

    finally:
        gurud-=1
        try:
            s.close()
        except:
            pass
        try:
            #input('??')
            driver.quit()
        except:
            pass  
        try:
            os.remove(f'{asd}.zip')
        except:
            pass
        if er:
            raise Exception('guru_token error')


    return token

def solvecaptcha(link,ua,key,td,proxystr,typed='def'):
    #if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
    if True:
        if False:
            #proxyforcaptchastr=proxystr
            proxyforcaptchastr='190.2.149.148:32208:3053cb26-374658:bbanxqm1jf'
        elif False:
            proxyforcaptchastr=proxystr_for_dr
        else:
            proxyforcaptchastr=proxystr
    else:
        try:
            global proxylist
            with lock:
                proxyforcaptchastr=proxylist[0]
                proxylist=proxylist[1:]
        except:
            proxyforcaptchastr=proxystr
    if typed=='def':
        tpd='FunCaptchaTask'
    else:
        tpd='ImageToTextTask'
    titid=0
    token=None
    try:
        if td[0]==True:
            #srr='https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html?theme=default'
            #srr='https://client-api.arkoselabs.com/v2/2CB16598-CB82-4CF7-B332-5990DB66F3AB/enforcement.ba4092d71b9c15de6b5f12c487d0fb2f.html'
            #srr=WebDriverWait(driver, 6).until(EC.element_to_be_clickable((By.XPATH,'//*[@title="Captcha Validation"]'))).get_attribute('src')
            srr='https://client-api.arkoselabs.com'
            #if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
            if tpd=='FunCaptchaTask':
                
                r=requests.post('https://api.capsolver.com/createTask',json={
                    "clientKey": "CAI-DE864DCFDA7F55A1FE70B42C47E4C179",
                    "task": {
                        "type": #"FunCaptchaTask",
                        'FunCaptchaTaskProxyless',

                        #"websitePublicKey": "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
                        #0152B4EB-D2DC-460A-89A1-629838B529C9
                        "websitePublicKey": key,
                        
                        "websiteURL": link,
                        
                        "userAgent": ua,
                        'funcaptchaApiJSSubdomain': srr,


                        # 'proxyType': 'http',
                        
                        # 'proxyAddress': proxyforcaptchastr.split(':')[0],
                        #     #proxyforanti,
                        # 'proxyPort': int(proxyforcaptchastr.split(':')[1]),
                        # 'proxyLogin': proxyforcaptchastr.split(':')[2],
                        # 'proxyPassword': proxyforcaptchastr.split(':')[3]
                    
                    

                        # 'proxyType': 'socks5',
                        # 'proxyAddress': proxyforcaptchastr.split(':')[0],
                        #     #proxyforcaptchastr,
                        # 'proxyPort': int(proxyforcaptchastr.split(':')[1]),
                        # 'proxyLogin': proxyforcaptchastr.split(':')[2],

                        # 'proxyPassword': pp

                    }
                })
                if r.json()['errorId']==0:
                    ti=r.json()['taskId']
                    #print(ti,'ti')
                else:
                    print(r.json(),'uebanka')
                    raise Exception(r.json()['errorDescription'])
                #time.sleep(5)
                rs=0
                if tpd=='FunCaptchaTask':
                    adada='api.capsolver.com'
                    kkk='CAI-DE864DCFDA7F55A1FE70B42C47E4C179'
                else:
                    adada='2captcha.com'
                    kkk='2be1c39bb553365d0c09f37b96bca7ac'
                while True:
                    #print(rs)
                    r=requests.post(f'https://{adada}/getTaskResult',json={'clientKey':kkk,'taskId':ti} )
                # r=requests.post(f'https://api.capsolver.com/getTaskResult&clientKey=CAI-DE864DCFDA7F55A1FE70B42C47E4C179?taskId={ti}')
                    try:
                        
                        if r.json()['status']=='ready':
                            token=r.json()['solution']['token']
                            print('found!',rs)
                            break
                        
                        elif r.json()['status']=='failed':
                            print(r.json(),'uebanka2')
                            raise Exception(r.json()['errorDescription'])
                    except:
                        print(r.json(),'uebanka2')
                        raise Exception(r.json()['errorDescription'])
                    #time.sleep(0.1)
                    
                    rs+=1
            else:
                data = {'key': '2be1c39bb553365d0c09f37b96bca7ac'}
                filed = {'file': open(f'tmppicsxevil/{typed}.jpg', 'rb'), 'submit': 'Upload and get the ID'}
                r = requests.post(f'http://2captcha.com/in.php',data=data,files=filed)
                print(r.text)
                ref = r.text.split('|')[-1]
                titid=ref
                while True:
                    
                    result = requests.get(f'http://2captcha.com/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=get&id={ref}')
                    res = result.text.split('|')[-1]
                    if 'CAPCHA_NOT_READY' not in res:
                        token=res
                        print(token)
                        break
                    time.sleep(0.5)

            
        else:
            raise Exception('SKIP CAPSOLVER')
    except Exception as x:
        if 'custom proxy connect failed' in str(x):
            td[2]=False
        if 'KeyboardInterrupt' in str(x):
            dn='KeyboardInterrupt'
            raise Exception('KeyboardInterrupt')
        else:
            print(repr(x))
            try:
                if td[1]==True:
                    #if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
                    if True:
                        r=requests.post('https://api.anycaptcha.com/createTask',json={
                            "clientKey": "9d1331af4f294ef6a95d9d6652796031",
                            "task": {
                                "type": "FunCaptchaTaskProxyless",
                                #"FunCaptchaTask",
                                #"websitePublicKey": "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
                                "websitePublicKey": key,
                                "websiteURL": link,


                                # 'proxyType': 'http',
                                # 'proxyAddress': proxystr.split(':')[0],
                                # 'proxyPort': int(proxystr.split(':')[1]),
                                # 'proxyLogin': proxystr.split(':')[2],
                                # 'proxyPassword': proxystr.split(':')[3],


                                # 'proxyType': 'socks5',
                                # 'proxyAddress': proxyforcaptchastr.split(':')[0],
                                #     #proxyforcaptchastr,
                                # 'proxyPort': int(proxyforcaptchastr.split(':')[1]),
                                # 'proxyLogin': proxyforcaptchastr.split(':')[2],
                                # 'proxyPassword': pp,


                                "userAgent": ua
                            }
                                })
                    else:
                        r=requests.post('https://api.anycaptcha.com/createTask',json={
                            "clientKey": "9d1331af4f294ef6a95d9d6652796031",
                            "task": {
                                "type": "FunCaptchaTaskProxyless",
                                #"FunCaptchaTask",
                                #"websitePublicKey": "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
                                "websitePublicKey": key,
                                "websiteURL": link,

                                "userAgent": ua
                            }
                                })

                    if r.json()['errorId']==0:
                        ti=r.json()['taskId']
                    else:
                        raise Exception(r.json()['errorDescription'])
                    #time.sleep(5)
                    while True:
                        r=requests.post('https://api.anycaptcha.com/getTaskResult',data={'clientKey':'9d1331af4f294ef6a95d9d6652796031','taskId':ti})
                        try:
                            if r.json()['status']=='ready':
                                #token=urllib.parse.unquote(r.json()['solution']['token'])
                                token=r.json()['solution']['token']
                                break
                        except:
                            raise Exception(r.json()['errorDescription'])
                else:
                    raise Exception('SKIP ANYCAPTCHA')
        

            except Exception as x:
                if 'KeyboardInterrupt' in str(x):
                    dn='KeyboardInterrupt'
                    raise Exception('KeyboardInterrupt')
                else:
                    print(repr(x))
                    
                    if td[2]==True:
                        #proxyforcaptchastr='45.82.65.183:25483:e8fd1276-77889:1rz78s5tyg7'    
                        try:
                            raise Exception('SKIP ANTI')
                            tct=time.time()
                            
                            if False:
                                print('ah ti bl0')
                                solver = funcaptchaProxyless()
                                solver.set_verbose(1)
                                solver.set_key("c9e1288c3e8ee413d3b5bca84dd0ad09")
                                solver.set_website_url(link)
                                solver.set_website_key(key)
                                solver.set_js_api_domain('client-api.arkoselabs.com')
                                token = solver.solve_and_return_solution()
                                if token != 0:
                                    print("result token: ")
                                else:
                                    print("task finished with error "+solver.error_code)
                            else:
                                r=requests.post('https://api.anti-captcha.com/createTask',json={
                                    "clientKey": "c9e1288c3e8ee413d3b5bca84dd0ad09",
                                    "task": {
                                        "type": "FunCaptchaTaskProxyless",
                                        #"FunCaptchaTask",
                                        #"websitePublicKey": "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
                                        "websitePublicKey": key,
                                        "websiteURL": #'https://client-api.arkoselabs.com/fc/gt2/public_key/2CB16598-CB82-4CF7-B332-5990DB66F3AB', 
                                        link,
                                        #'proxyType': 'http',
                                        #'proxyAddress': proxyforanti,
                                        #'proxyPort': int(proxystr.split(':')[1]),
                                    # 'proxyLogin': proxystr.split(':')[2],
                                    # 'proxyPassword': proxystr.split(':')[3],


                                        #'proxyType': 'socks5',
                                       # 'proxyAddress': proxyforcaptchastr.split(':')[0],
                                            #proxyforcaptchastr,
                                        #'proxyPort': int(proxyforcaptchastr.split(':')[1]),
                                        #'proxyLogin': proxyforcaptchastr.split(':')[2],
                                       # 'proxyPassword': proxyforcaptchastr.split(':')[3],


                                    # "data":"{\"blob\":\"undefined\"}",
                                    'funcaptchaApiJSSubdomain': 'client-api.arkoselabs.com',
                                        
                                        'userAgent': ua
                                    }#,"languagePool":"en"
                                        })

                                if r.json()['errorId']==0:
                                    ti=r.json()['taskId']
                                else:
                                    raise Exception(r.json()['errorDescription'])
                                #time.sleep(10)
                                tkl=''.join(random.choices(string.ascii_uppercase + string.digits, k=8))+str(randint(1,19))
                                
                                global tokenlocal
                                tokenlocal[tkl]=None
                                
                                def get_this(ti,u,tkl):
                                    global tokenlocal
                                    try:
                                        while tokenlocal[tkl]==None:
                                            r=requests.post('https://api.anti-captcha.com/getTaskResult',json={'clientKey':'c9e1288c3e8ee413d3b5bca84dd0ad09','taskId':ti})
                                            try:
                                                #print(u)
                                                if r.json()['status']=='ready':
                                                    #token=urllib.parse.unquote(r.json()['solution']['token'])
                                                    tokenlocal[tkl]=r.json()['solution']['token']
                                                    #print(tokenlocal)
                                                    #token=token.replace(r'https%3A%2F%2Ffuncaptcha.com',r'https%3A%2F%2Fclient-api.arkoselabs.com')
                                                    #token=token.replace('|at=40|','|at=40|sup=1|')
                                                    
                                                    break
                                            except:
                                                print('pidor')
                                                raise Exception(r.json()['errorDescription'])
                                    except:
                                        pass
                                    #print('VSE NAHUI')

                                gh=[]
                                for i in range(50):
                                    stancia=threading.Thread(target=get_this,args=(ti,i,tkl,))
                                    stancia.start()
                                    gh.append(stancia)
                                    time.sleep(0.25)

                                while tokenlocal[tkl]==None:
                                    pass

                                token=tokenlocal[tkl]
                                tokenlocal.pop(tkl)
                                print(time.time()-tct)

                         #2491753165b5c4e45.8863903905|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|                         cdn_url=https%3A%2F%2Fclient-api.funcaptcha.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com       |surl=https%3A%2F%2Fclient-api.funcaptcha.com|smurl=https%3A%2F%2Fclient-api.funcaptcha.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                     #wrk#52763d38b3272af86.5780160104|r=ap-southeast-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|ag=101             |cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-ap-southeast-1.arkoselabs.com  |surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                         #409175316a15cadc2.9201174105|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000     |pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|                    cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                        
                    #anti#863d388e2c1cde4.9953769805  |r=eu-west-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|rid=95|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                        #
                        #wrk#95863d28ecfa4cad5.6608441305|r=eu-west-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|sup=1|rid=63|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager

                    #browser    #3781756156a213bf2.7879287305|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40 |rid=58|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                    #solveman   #8501756154f4a8ec6.2892938705|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|lang=en|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                        except Exception as x:
                            if 'KeyboardInterrupt' in str(x):
                                dn='KeyboardInterrupt'
                                raise Exception('KeyboardInterrupt')
                            else:
                                try:
                                    print(repr(x))
                                    if td[3]==True:
                                        raise Exception('SKIP 2CAP')
                                    #91617527d3644c7d9.5784880601|r=us-east-1|meta=7|meta_height=325|metabgclr=%23ffffff|metaiconclr=%23757575|mainbgclr=%23ffffff|maintxtclr=%231B1B1B|guitextcolor=%23747474|lang=en|pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA|at=40|ht=1|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-us-east-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                                    #22117527cd4728437.8723375505|r=eu-west-1|meta=7|meta_height=325|metabgclr=%23ffffff|metaiconclr=%23757575|mainbgclr=%23ffffff|maintxtclr=%231B1B1B|guitextcolor=%23747474|lang=en|pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA|at=40|ht=1       |cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager
                                    
                                    tct=time.time()
                                    api_key = '2be1c39bb553365d0c09f37b96bca7ac'

                                    solver = TwoCaptcha(api_key,defaultTimeout=360,pollingInterval=1)
                                    try:
                                        token = solver.funcaptcha(#sitekey='2CB16598-CB82-4CF7-B332-5990DB66F3AB',
                                                                                        sitekey= key,
                                                                    url=link,
                                                                    surl='https://client-api.arkoselabs.com'
                                    # ,proxy={
                                    #     'type': 'SOCKS5',
                                    #     'uri': proxyforcaptchastr
                                    # }
                                        )

                                        titid=token['captchaId']
                                        token=token['code']
                                        
                                    except Exception as zxc:                         
                                        if 'KeyboardInterrupt' in str(x):
                                            dn='KeyboardInterrupt'
                                            raise Exception('KeyboardInterrupt')
                                        else:
                                            print(str(zxc))
                                            #print(proxy_id)#
                                            return None
                                    print(time.time()-tct)

                                except Exception as x:
                                    if 'KeyboardInterrupt' in str(x):
                                        dn='KeyboardInterrupt'
                                        raise Exception('KeyboardInterrupt')
                                    else:
                                        print(repr(x))
                                        token=None
                                        if key=='2CB16598-CB82-4CF7-B332-5990DB66F3AB':
                                            trash=80
                                        else:
                                            trash=90
                                        
                                        asd=0
                                        while token==None:
                                            try:
                                                if False:
                                                    capmonster = FuncaptchaTask("1c88a15804075c4ac70db8a5855e0b88__recognizingThreshold_100")
                                                    #capmonster.set_user_agent(ua)

                                                    # capmonster.set_proxy(
                                                    #     proxy_type='http',
                                                    #     proxy_address=proxyforcaptchastr.split(':')[0],
                                                    #     proxy_port=int(proxyforcaptchastr.split(':')[1]),
                                                    #     proxy_login=proxyforcaptchastr.split(':')[2],
                                                    #     proxy_password=proxyforcaptchastr.split(':')[3]
                                                    # )
                                                    task_id = capmonster.create_task(
                                                    link
                                                    ,key
                                                    #,no_cache=True
                                                    #, api_js_subdomain='https://client-api.arkoselabs.com'
                                                    )
                                                    result = capmonster.join_task_result(task_id)
                                                    token=result.get("token")
                                                else:
                                                    
                                                    r=requests.post('https://api.capmonster.cloud/createTask',json={
                                                        "clientKey": "261963e421a5c627816281c19539d59c",
                                                        "task": {
                                                            "type": "FunCaptchaTaskProxyless",
                                                            #'FunCaptchaTask',

                                                            "websitePublicKey": key,
                                                            "websiteURL": 
                                                            link,
                                                            "recognizingThreshold" : trash,
                                                            'userAgent': ua,
                                                            'nocache':True
                                                            # 'proxyType': 'http',
                                                            # 'proxyAddress': proxyforcaptchastr.split(':')[0],
                                                            # 'proxyPort': int(proxyforcaptchastr.split(':')[1]),
                                                            # 'proxyLogin': proxyforcaptchastr.split(':')[2],
                                                            # 'proxyPassword': proxyforcaptchastr.split(':')[3],

                                                        }#,"languagePool":"en"
                                                            })


                                                    if r.json()['errorId']==0:
                                                        ti=r.json()['taskId']
                                                    else:
                                                        raise Exception(r.json()['errorDescription'])
                                                    #time.sleep(10)
                                                    rs=0
                                                    #print('papkasihat')
                                                    while True:
                                                       # print(rs)
                                                        r=requests.post('https://api.capmonster.cloud/getTaskResult/',json={'clientKey':'261963e421a5c627816281c19539d59c','taskId':ti})
                                                    
                                                        try:
                                                            
                                                            if r.json()['status']=='ready':
                                                                token=r.json()['solution']['token']
                                                                
                                                                print('found!',rs)
                                                                break
                                                            
                                                            elif r.json()['status']=='failed':
                                                                raise Exception(r.json()['errorDescription'])
                                                        except:
                                                            print(r.json())
                                                            raise Exception(r.json()['errorDescription'])
                                                        time.sleep(0.5)
                                                        rs+=1
                                            except Exception as zxc:
                                                asd+=1
                                                if asd>2:
                                                    raise Exception('piazda monsntru')
                                                pass

                    else:
                        print('SKIP LONG CAPTCHAS')
                        #print(proxy_id)#
                        return False

    #print(token)            
    return token,titid









prev='1455854481959268352'
#pip=int(input('SKOLKO? GANDON PIDORAS GNIDA - '))
#for xuiii in range(pip):
systemn=input('SYSTEM NUMBER - ')
if default==True:
    systemn=f"{systemn}/def"

odnovrem_t=120
odnovrem_t=1
#tor_g=[['omyfowavem@outlook.com', 'FIAQXWG410'], ['gefyfamur@outlook.com', '0TBS8F3Q16'], ['ujudocyxe@outlook.com', 'FIVF9JDS10'], ['uqitojufim@outlook.com', '0PM55G4G9'], ['keryhedab@outlook.com', 'O0FJLSZB7'], ['moreniryje@outlook.com', 'XJ0NKVLU16'], ['apitemyxa@outlook.com', '2EZTM1JU19'], ['umijomaqi@outlook.com', 'VPHM27S17'], ['ifoduqytys@outlook.com', 'WC5GPQAW15'], ['guliwihohexo@outlook.com', '5DPEQ6HN19'], ['vogaxatube@outlook.com', 'O4KPD0AH4'], ['nawinyqakawu@outlook.com', 'TN8ACQJ313'], ['ubyvyfujy@outlook.com', '9OQKV98T7'], ['vorapelodah@outlook.com', 'GVBRGOLG2'], ['licohejovug@outlook.com', 'X7YNKE6P2'], ['dawezisan@outlook.com', 'KJSJA2FM6'], ['epihuloroqos@outlook.com', 'I2AXZW201'], ['tiharihugusu@outlook.com', 'LMVIWXPJ6'], ['ematorovi@outlook.com', 'LERFWCCJ13']]
#tor_g=[['bYvuloxopU@hotmail.com', 'KNY6KGSA12'], ['ReSozaxehe46@hotmail.com', 'S6RSHH543'], ['amymagaqa@hotmail.com', 'TEHXMA2E14'], ['WaTobalUg@hotmail.com', 'P0IWRSY516'], ['ulyzOtuRapE_Extra@hotmail.com', 'X1Y74A4614'], ['IjecosaxY@hotmail.com', '3K2VFGMH11'], ['ceqewycitud@hotmail.com', 'JPXB72353'], ['umovAkopar@hotmail.com', 'Z7M1LN9312'], ['HabepYbyku_games67@hotmail.com', 'OHGVANB219'], ['xaWubIgybUXy87__eth@hotmail.com', 'Z03NIK3316'], ['yLohaHake76@hotmail.com', 'F6H7155D14'], ['fofymodaH_eco@hotmail.com', 'LKDBT1QN11'], ['exomozitanuc@hotmail.com', 'UB10R2O712'], ['QilYdaRav_Gym95@hotmail.com', 'RI34DQUK18'], ['lArujUZeQa@hotmail.com', '1V22QP3T6'], ['gykAkynoxo@hotmail.com', 'TAUSFGQS19'], ['imohinAxAH35@hotmail.com', 'YJHIYT8318'], ['vujaFolipyp@hotmail.com', 'YQDL6DR13'], ['asoLifehyXo@hotmail.com', 'K15EA82V8'], ['nozuqOcOjiw@hotmail.com', 'KPF9GEM419']]
tor_g=[]
cl_d={}
for i in range(odnovrem_t):

    cl_d[i]=0
erka=[]
gnumber=200*odnovrem_t
if gnumber<500:
    gnumber=500
gnumber=1000
changing_api_rn=False
sending_req_rn=False
donede=0
er=0
fer=0
cur_dr=False
curph=[]
# try:
#     ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',None)
#     phone,idp=ph.get_phone('GB')
#     print(phone)
#     curph.append(phone)
# except Exception as x:
#     print(repr(x))



def add_phone_cunt(head,cookies,pasw):
    lock=threading.Lock()
    global curph
    pay={"input_flow_data":{"flow_context":{"debug_overrides":{},"start_location":{"location":"settings"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
    r=requests.post('https://api.twitter.com/1.1/onboarding/task.json?flow_name=add_phone',headers=head,cookies=cookies,json=pay,proxies=proxy)

    flow=r.json()['flow_token']

    pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"DeviceAssocEnterPassword","enter_password":{"password":pasw,"link":"next_link"}}]}
    r=requests.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,cookies=cookies,json=pay,proxies=proxy)
    flow=r.json()['flow_token']

    if len(curph)<odnovrem_t:
        phone=''
        while '+44' not in phone:
            phone,idp=ph.get_phone('GB')
        print(phone)
        lock=threading.Lock()
        with lock:
            curph.append([phone,idp])
    else:
        lock=threading.Lock()
        with lock:
            phone=curph[0][0]
            idp=curph[0][1]
            curph=curph[1:]
            curph.append(phone)

    for i in range(5):
        try:
            pay={"phone":phone,"use_voice":False,"sim_country_code":"GB","send_auto_verify_hash":False,"flow_token":flow}
            r=requests.post('https://api.twitter.com/1.1/onboarding/begin_verification.json',headers=head,cookies=cookies,json=pay,proxies=proxy)
            

            r.json()['normalized_phone_number']
            if r.status_code==200:
                print('codik jdems')
                try:
                    code=ph.get_code(idp,8)
                except:
                    raise TimeoutException('no code xd')

                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"EnterPhoneForAssociation","enter_phone":{"country_code":"GB","phone_number":phone,"setting_responses":[{"key":"phone_discoverability_setting","response_data":{"boolean_data":{"result":False}}},{"key":"privacy_consent_setting","response_data":{"boolean_data":{"result":True}}}],"link":"next_link"}},{"subtask_id":"PhoneAssociationVerificationAlert","alert_dialog":{"link":"next_link"}},{"subtask_id":"PhoneAssociationVerification","phone_verification":{"code":code,"link":"next_link","normalized_phone":phone,"by_voice":False}}]}
                r=requests.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,cookies=cookies,json=pay,proxies=proxy)

                flow=r.json()['flow_token']
                break
            else:
                raise Exception('e400 phone')

        except Exception as x:
            

            print(repr(x))

            with lock:
                curph.remove(phone)

            if i==4:
                raise Exception(x)
            phone=''    
            while '+44' not in phone:
                phone,idp=ph.get_phone('GB')
            print(phone)

            with lock:
                curph.append([phone,idp])


    

    pay={"flow_token":flow,"subtask_inputs":[]}
    r=requests.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,cookies=cookies,json=pay,proxies=proxy)
    return True,phone
starting=1

localsystemn=1

with lock:
    
    ####
    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','r') as acp_create2:
        acp_create2=acp_create2.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','a') as acp_create:
        acp_create.writelines(acp_create2) 

    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','w') as acp_create2:
        acp_create2.writelines(['']) 
    ####


    ####
    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','r') as acp_create2:
        acp_create2=acp_create2.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/not403.txt','a') as acp_create:
        acp_create.writelines(acp_create2) 

    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','w') as acp_create2:
        acp_create2.writelines(['']) 
    ####


    ####
    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/requested.txt','r') as acp_create2:
        acp_create2=acp_create2.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','a') as acp_create:
        acp_create.writelines(acp_create2) 

    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/requested.txt','w') as acp_create2:
        acp_create2.writelines(['']) 
    ####


    ###
    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/mailban.txt','r') as mailbana2:
        mailbana2=mailbana2.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as mailbana:
        mailbana.writelines(mailbana2) 

    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/mailban.txt','w') as mailbana:
        mailbana.writelines(['']) 
    ###



tokens_twt=[]
def changing(ls):
    while True:
        while True:
            try:
                r=requests.get(ls, headers={'User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36'})
                if r.status_code==200:
                    print('changed')

                    break
            except Exception as x:
                #
                try:
                    if 'Too many same requests' in r.text:
                        break
                except:
                    pass
                print(repr(x))
                time.sleep(2)

        time.sleep(30)

def farm_tokens(proxystr,ts):
    global tokens_twt
    global gurud
    time.sleep(ts)
    while True:
        if len(tokens_twt)>=odnovrem_t or gurud>=13: #gurud>=odnovrem_t/8:
            time.sleep(1)
        else:
            token=False
            if True:
                token=solveman.solveman('2CB16598-CB82-4CF7-B332-5990DB66F3AB',
                    #proxystr='185.130.226.44:11982'
                    #proxystr='s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                    #proxystr='s1.op-proxy.com:25000:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                    proxystr='s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                    #proxystr=random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'])
                    #proxystr=proxystr
                    #proxystr=None
                    # #,ua=head['user-agent']
                    ,ua=None
                    ,pid=None
                    
                    )
            else:
                try:
                    token=guru_token('2CB16598-CB82-4CF7-B332-5990DB66F3AB',
                    #proxystr
                    #random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'])
                    's7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                    ,None,None)
                except:
                    time.sleep(random.randint(1,5))
            if token:
                tokens_twt.append([token,time.time()])

        for tt in tokens_twt:
            if tt[1]+1.5*60<time.time():
                #print('lishnie tokens WARNING')
                tokens_twt.remove(tt)            

if False:
    gf=threading.Thread(target=changing,args=('https://mobileproxy.space/reload.html?proxy_key=3cff366f92a79f04a6888c9e1741ddd2',))
    gf.start()

proxystr='s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
for f in range(odnovrem_t):

    gf=threading.Thread(target=farm_tokens,args=(proxystr,f,))
    gf.start()
    
while True:

    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acpstart:
        acpstart=acpstart.readlines()
    
    #tocr=gnumber-len(acpstart)%gnumber
    
    tocr=gnumber-len(acpstart)
    if tocr<0 and starting==0:
        tocr=gnumber-100
    
    starting=0
    
    while True:
        print(tocr)
        #print(len(global_dop_system))
        if tocr<=0 and len(global_dop_system)==15:
            break
        
        if False:
            while sending_req_rn:
                time.sleep(0.5)
            changing_api_rn=True
            while cur_dr:
                time.sleep(0.5)

            changecr()

            changing_api_rn=False
            print(tor_g)
            print(len(tor_g),'tor_g')
            print('WARNING: did -',donede,'fatalErr -',fer,'allerr -',er,'req again - ', total_to_req_again)

        

        def main_create(number_t,proxy,proxystr):
            global donede
            global tokens_twt
            global er
            global ersin
            global tocr
            global tor_g
            global cl_d
            global fer
            
            writ=False
            repmail=False
            #ersin=0
            # proxystr='185.130.226.44:11000'
            # proxy={
            #         "https" : f"https://{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
            # }

            while True:
                if True:
                    if tocr<=0 and len(global_dop_system)==15:
                        break
                    
                    print(len(tor_g),'tor_g')
                    print('WARNING: did -',donede,'fatalErr -',fer,'allerr -',er,'req again - ', total_to_req_again)


                cl=cl_d[number_t]
                print(proxy)
                if len(tor_g)>odnovrem_t*2:
                    tor=tor_g[number_t]      
                else:
                    tor=[]
                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acppervi:
                    acppervi=acppervi.readlines()  
                
                # s=requests.Session()
                # retry = Retry(connect=3, backoff_factor=0.5)
                # #adapter = HTTPAdapter(max_retries=retry)
                # adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,max_retries=retry)
                # s.mount('http://', adapter)
                # s.mount('https://', adapter)
                # #s.mount('https://', DESAdapter(max_retries=3))
                # print(s.get('https://ip-score.com/fulljson',proxies=proxy).text)

                try:
                    def check_tor(tor):
                            zxcxzc=0
                            while True:
                                if len(tokens_twt)==0:
                                    time.sleep(0.2)
                                else:
                                    with lock:
                                        token,chtert=tokens_twt[0]
                                        tokens_twt.pop(0)

                                    if chtert+1*60>time.time():
                                        break
                            try:
                                somer=False
                                global cur_dr
                                global fer
                                prej={"response":"{\"rf\":{\"c745cd715da09f6bf841ddfdc7631c3c1b3505a63591249cbd7ed8b9a09ceab5\":-29,\"a147ea454929c07e6e2fc527042661e445a5686633c71103727a9a40bdf0a093\":-1,\"ad5131ebc87025653fd9ca9c5d12adc248f1903e8d97f05b33db419fb9f05436\":28,\"a3f296f8de01ced8a822c73af4c7ce71bc7d6a653373917a50b43adbf92f0cd6\":40},\"s\":\"chXoyNvk8GIM2GcQJ92nxPjLBBsQywkhOjlp6xQMnSATAnvccnbtuZQPnWQLPWJyOGESQxeBSdIr-OqtITrVBKAlVlLKNMaMgN4bIr92JWgqWq_u4LzceXHhwEasroyOHffbOkHjSf7A4aib8BvDulYjxUXFUcNY4R7X_8gkcqfQx_e44Qw3LwYXiTCUaM2Cz4FpyG7EMqSxMPw-xO9zCkMxRsIvaFwk1JPTt99Qu3LteAluyG_5no7ewurcjnI5PFAL4c6idD5Bc8s8WuPRdfzM_h1FIim-6EWkpGaNXIw19NbJ_rsfFtRa-Sz3s8MDNqQPM-XrY-TGLENKRvwA8gAAAYW8QQUi\"}"}

                                MAIL=tor[0]
                                MPASS=tor[1]
                                s=requests.Session()
                                retry = Retry(connect=3, backoff_factor=0.5)
                                #adapter = HTTPAdapter(max_retries=retry)
                                adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,max_retries=retry)
                                s.mount('http://', adapter)
                                s.mount('https://', adapter)
                                #s.mount('https://', DESAdapter(max_retries=3))
                                
                                


                                d1=randint(1,28)
                                d2=randint(1,12)
                                d3=randint(1990,2002)

                                pzxc=0
                                if False:
                                    try:
                                        # while cur_dr:
                                        #     time.sleep(0.1)
                                        cur_dr=True
                                        dr=selenium_driver_gen.sel_driver_gen()
                                        driver,proxdict,ua =dr.gen(MAIL.split("@")[0],proxystr_for_dr)
                                        print(driver.session_id)
                                        if False:
                                            try:
                                                try:
                                                    driver.get('https://twitter.com')
                                                    driver.set_window_size(randint(1549,1700), randint(900,1100))
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@href="/i/flow/signup"]'))).click()
                                                except TimeoutException:
                                                    driver.get('https://twitter.com/i/flow/signup')
                                                    driver.set_window_size(randint(1549,1700), randint(900,1100))
                                                try:
                                                    el=WebDriverWait(driver, 6).until(EC.element_to_be_clickable((By.XPATH,'//*[@autocomplete="name"]')))
                                                except TimeoutException:
                                                    pass
                                                try:
                                                    WebDriverWait(driver, 3).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[1]/div/div/div[5]'))).click()
                                                except TimeoutException:
                                                    pass
                                                    #el=WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@autocomplete="name"]')))
                                                el=WebDriverWait(driver, 6).until(EC.element_to_be_clickable((By.XPATH,'//*[@autocomplete="name"]')))
                                                
                                            except TimeoutException:
                                                mmm=False
                                                raise Exception('bad start')
                                        elif True:
                                            driver.set_window_size(randint(1549,1700), randint(900,1100))
                                            driver.get('https://twitter.com/i/flow/signup')
                                            
                                        else:
                                            driver.get('https://twitter.com/i/flow/signup')
                                            time.sleep(10)

                                        

                                    

                                        
                                        while True:
                                            try:
                                                # print(1)

                                                cookies = driver.get_cookies()
                                                cc=[]
                                                for cookie in cookies:
                                                        cc.append(f"{cookie['name']}={cookie['value']}")
                                                        cookie_obj = requests.cookies.create_cookie(domain=cookie['domain'],name=cookie['name'],value=cookie['value'])
                                                        s.cookies.set_cookie(cookie_obj)

                                                cc='; '.join(cc)
                                                head = requests.utils.default_headers()
                                                #head['cookie']=cc
                                                head=dr.network(driver,['authorization','x-csrf-token','flow_token','x-guest-token'],head)
                                                cookie_obj = requests.cookies.create_cookie(domain='.twitter.com',name='ct0',value=head['x-csrf-token'])
                                                s.cookies.set_cookie(cookie_obj)
                                                head['user-agent']=ua
                                                s.headers['User-Agent']=ua

                                                #print(2)
                                                pay={"input_flow_data":{"flow_context":{"debug_overrides":{},"start_location":{"location":"unknown"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
                                                zxc=0
                                                if False:
                                                    while True:
                                                        try:
                                                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json?flow_name=signup',headers=head,timeout=15,json=pay,proxies=proxy,cookies=s.cookies.get_dict())
                                                        except:
                                                            zxc+=1
                                                else:
                                                    r=s.post('https://api.twitter.com/1.1/onboarding/task.json?flow_name=signup',headers=head,timeout=30,json=pay,proxies=proxy,cookies=s.cookies.get_dict())
                                                        
                                                #r.close() 
                                                #print(r)
                                                try:
                                                    flow=r.json()['flow_token']
                                                except:
                                                    raise Exception(r.text)


                                                for i in r.headers:
                                                    if 'csrf' in i:
                                                        print(r.headers[i])
                                                        s.headers['x-csrf-token']=r.headers[i]

                                                break

                                            except Exception as x:
                                                print(repr(x),'driver')
                                                pzxc+=1
                                            
                                                #time.sleep(2)
                                            if True:
                                                if pzxc==1:
                                                    time.sleep(2)
                                                
                                                elif pzxc==2:
                                                    driver.set_window_size(randint(1549,1700), randint(900,1100))
                                                    driver.get('https://twitter.com/i/flow/signup')
                                                    time.sleep(2)

                                                elif pzxc>2:
                                                    raise Exception('pipi1')
                                                

                                            elif pzxc>2:
                                                raise Exception('pipi1')
                                        
                                    except Exception as x:
                                        print(repr(x))   
                                        if pzxc>2:
                                            if False:
                                                if writ==False:
                                                    with lock:
                                                        with open(f'/root/work/create_and_unban_SYSTEM/{systemn}/hotc_clear.txt','a') as mim:
                                                            mim.writelines(f"{MAIL}:{MPASS}\n")
                                                            writ=True
                                                pass
                                        
                                        try:
                                            driver.quit()
                                        except:
                                            pass  
                                        cur_dr=False
                                        raise Exception('pipi2')    

                                    finally:
                                        print('quit')
                                        try:
                                            driver.quit()
                                        except:
                                            pass  
                                        try:
                                            os.remove(f'{MAIL.split("@")[0]}.zip')
                                        except:
                                            pass
                                        cur_dr=False
                                    
                                    
                                else:
                                    software_names = [SoftwareName.CHROME.value]
                                    operating_systems = [OperatingSystem.WINDOWS.value]   
                                    user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=1)

                                    userAgent = user_agent_rotator.get_random_user_agent()
                                    assa=f"{randint(100,999)}.{randint(1,99)}"
                                    userAgent=userAgent.replace(f"Chrome/{userAgent.split('Chrome/')[-1].split(' ')[0]}",f"Chrome/{randint(80,111)}.0.{randint(0,1)}.{randint(0,1)}")
                                    userAgent=userAgent.replace(f"Safari/{userAgent.split('Safari/')[-1].split(' ')[0]}",f"Safari/{assa}")
                                    userAgent=userAgent.replace(f"AppleWebKit/{userAgent.split('AppleWebKit/')[-1].split(' ')[0]}",f"AppleWebKit/{assa}")
                                    userAgent=userAgent.replace(f"Windows NT {userAgent.split('Windows NT ')[0][:2]}",f"Windows NT {randint(1,9)}.{randint(1,9)}")
                                    uak=userAgent
                                    ua=uak
                                    #ua=userAgent
                                    #ua=f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(92,111)}.0.0.0 Safari/537.36'
                                    #ua=f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'
                                    #head = requests.utils.default_headers()
                                    
                                    ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
                                    
                                    head={}
                                    head['user-agent']=ua

                                    ggtw=get_csrf_twitter(head,proxy)

                                    head['x-csrf-token']=ggtw['x-csrf-token']
                                    head['x-guest-token']=ggtw['x-guest-token']
                                    head['authorization']='Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
                                    
                                    head['x-twitter-active-user']= 'yes'
                                    head['x-twitter-client-language']= 'en'

                                    cookie_obj = requests.cookies.create_cookie(domain='.twitter.com',name='ct0',value=head['x-csrf-token'])
                                    s.cookies.set_cookie(cookie_obj)
                                    s.headers['User-Agent']=ua

                                        #mobile
                                    #   {"input_flow_data":{"requested_variant":"{\"signup_type\":\"phone_email\"}","flow_context":{"debug_overrides":{},"start_location":{"location":"splash_screen"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
                                    
                                    if False:#mobile
                                        pay={"input_flow_data":{"requested_variant":"{\"signup_type\":\"phone_email\"}","flow_context":{"debug_overrides":{},"start_location":{"location":"splash_screen"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
                                    
                                    else:
                                        pay={"input_flow_data":{"flow_context":{"debug_overrides":{},"start_location":{"location":"unknown"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
                                    #time.sleep(random.randint(6,15))
                                    r=s.post('https://api.twitter.com/1.1/onboarding/task.json?flow_name=signup',headers=head,timeout=30,json=pay,proxies=proxy,cookies=s.cookies.get_dict())
                                                        

                                    try:
                                        flow=r.json()['flow_token']
                                    except:
                                        raise Exception(r.text)


                                    for i in r.headers:
                                        if 'csrf' in i:
                                            print(r.headers[i])
                                            s.headers['x-csrf-token']=r.headers[i]



                                payn={"method":"getNickName",
                                            "count_result":1,
                                            "len_nick_min":6,
                                            "len_nick_max":12
                                        }

                                LOGIN=None
                                
                                xui=0
                                while LOGIN==None:
                                    try:
                                        rr=requests.get('https://random-data-api.com/api/v2/users',timeout=2)#,proxies=proxy)
                                        fl=rr.json()['first_name']
                                        ll=rr.json()['last_name']
                                        r=fl+' '+ll
                                        pid=False
                                        LOGIN=r
                                        break
                                    except Exception as x:
                                        if xui==3:
                                            print(repr(x))
                                            raise Exception('xuita')
                                        

                                    try:
                                        rr=requests.get('https://api.namefake.com/',timeout=2)#,proxies=proxy)
                                        rr=rr.json()['name'].split(' ')
                                        r=' '.join(rr[:randint(1,len(rr))])
                                        if r.startswith('Miss') or r.startswith('Mr') or r.startswith('Mrs') or r.startswith('Dr') or r.startswith('Ms') or r.startswith('Prof'):
                                            r=' '.join(rr[:randint(2,len(rr))])
                                        pid=False
                                        LOGIN=r
                                        break
                                    except Exception as x:
                                        if xui==3:
                                            print(repr(x))
                                            raise Exception('xuita')
                                    
                                    try:
                                        r=requests.post('https://rustxt.ru/api/index.php',timeout=2,data=payn,proxies=proxy).json()[0]
                                        pid=True
                                        
                                        if len(r)>4:
                                            if randint(0,100)>50:
                                                r=r[:4]+random.choice(['_','.', '. ', ' ',' '])+r[5:]
                                        LOGIN=r
                                    except Exception as x:
                                        if xui==3:
                                            print(repr(x))
                                            raise Exception('xuita')
                                    try:
                                        r=requests.post('https://rustxt.ru/api/index.php',timeout=2,data=payn,proxies=proxy).json()[0]
                                        pid=True

                                        if len(r)>4:
                                            if randint(0,100)>50:
                                                r=r[:4]+random.choice(['_','.', '. ', ' ',' '])+r[5:]
                                        payn2={"method":"getNickName",
                                            "count_result":1,
                                            "len_nick_min":2,
                                            "len_nick_max":4
                                        }        
                                        r2=requests.post('https://rustxt.ru/api/index.php',timeout=2,data=payn2,proxies=proxy).json()[0]
                                        LOGIN=r+r2
                                    except Exception as x:
                                        if xui==5:
                                            print(repr(x))
                                            raise Exception('xuita')
                                    xui+=1
                                    time.sleep(2)
                                if pid:
                                    ll=''
                                    for i in LOGIN:
                                        if randint(0,20)>16:
                                            i=i.capitalize()
                                        ll+=i
                                    LOGIN=ll  
                                
                                #if default==False:
                                if True:
                                    desr=random.choice(['_', ' ','|', ' ', ' ',' ','!'])
                                    if desr=='|':
                                        desr=random.choice([' ',''])+desr+random.choice([' ',''])


                                    tord=[]
                                    lr=''
                                    if default==False:
                                        lrd=['eth','sol','gym','master','infl','crypto','nft','games','solana','rtx','beast','hyper','first','eco','forward','lgbt','extra','lucky','boss','genius','high','low','giga','mega','super','ultra','next','rich','drop','dope','swag','drip','clown','ufo','TopG','not','cracked','drill','rapper','lover','racks','builder','kun','uwu','cat','dj','$','#','lion','puff','lol','key','tiger','music','YT','TTV','fortnite','curl','cola','league','legend','coc','twt','monkey','fish','beat','pow','102','101','1996','666','999','gang','black','red','code','gtr','bmw','porcshe','school','mercedes','asia','japan','mic','crazy','hot','green','blue','chaser', 'champ','card','neitrone','throne','uni','toes','feet','palm','stone','vcc','die','diamond','death','spider','lil','shiba','big']
                                    
                                    else:
                                    
                                        lrd=['gym','master','infl','games','rtx','beast','hyper','first','eco','forward','lgbt','extra','lucky','boss','genius','high','low','giga','mega','super','ultra','next','rich','drop','dope','swag','drip','clown','ufo','TopG','not','cracked','drill','rapper','lover','racks','builder',    'kun','uwu','cat','dj','$','#','lion','puff','lol','key','tiger','music','YT','TTV','fortnite','curl','cola','league','legend','coc','twt','monkey','fish','beat','pow','102','101','1996','666','999','gang','black','red','code','gtr','bmw','porcshe','school','mercedes','asia','japan','mic','crazy','hot','green','blue','chaser', 'champ','card','neitrone','throne','uni','toes','feet','palm','stone','vcc','die','diamond','death','spider','lil','shiba','big']
                                    
                                    
                                    if randint(1,100)>10:

                                        if randint(1,100)>35:
                                            tord.append(randint(0,100))

                                            if randint(0,100)>2:
                                                lr=desr+lr

                                        if randint(1,100)>50:
                                            somer=True
                                            lr=random.choice(lrd)

                                            rgt=randint(1,100)
                                            if rgt>70:
                                                lr=lr.capitalize()
                                            elif rgt>50:
                                                lr=lr[0].capitalize()+lr[1:]

                                            lr=desr+lr
                                            tord.append(lr)


                                        if randint(1,100)>50:
                                            somer=True
                                            try:
                                                lrd.remove(lr)
                                            except:
                                                pass
                                            lr=random.choice(lrd)

                                            rgt=randint(1,100)
                                            if rgt>70:
                                                lr=lr.capitalize()
                                            elif rgt>50:
                                                lr=lr[0].capitalize()+lr[1:]

                                            lr=desr+lr
                                            tord.append(lr)


                                        random.shuffle(tord)

                                        for ing in tord:
                                            LOGIN+=str(ing)

                                name=LOGIN
                                        



                                # print(head)
                                # print(s.cookies.get_dict())
                                

                                #print('flow_name=signup')


                                #time.sleep(random.randint(4,8))
                                if '@gmx' in MAIL:
                                    typegh='gmx'
                                elif '@gmail' in MAIL:
                                    typegh='gmail'
                                elif '@outlook' in MAIL or '@hotmail' in MAIL:
                                    typegh='hot'
                                elif '@mail' in MAIL:
                                    typegh='mail'
                                elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                                    typegh='rambler'
                                for tritka in range(10):
                                    try:
                                        mm=mmail.mail_by_login(MAIL,MPASS,typegh)
                                        break
                                    except Exception as xxzx:
                                        if tritka>8:
                                            raise Exception(xxzx)
                                        time.sleep(1)
                                mail=MAIL

                                pay={"email":mail,"display_name": name,"flow_token":flow}
                                #time.sleep(random.randint(6,15))

                                r=s.post('https://api.twitter.com/1.1/onboarding/begin_verification.json',headers=head,timeout=15,json=pay,proxies=proxy)
                                #r.close() 
                                for i in r.headers:
                                    if 'csrf' in i:
                                        print(r.headers[i])
                                        s.headers['x-csrf-token']=r.headers[i]

                                if r.status_code==400:
                                    try:
                                        tor_g.remove(tor)
                                    except:
                                        pass
                                    tor=[]
                                    try:
                                        print(r.text)
                                    except:
                                        pass
                                    raise Exception('begin e400')

                                #print('begin twitter')

                                #time.sleep(random.randint(6,15))
                                try:
                                    js_chal=s.get('https://twitter.com/i/js_inst?c_name=ui_metrics',headers=head,timeout=15,proxies=proxy).text
                                    #print(len(js_chal))
                                    j_s=js_chal.split("'s':'")[-1].split("'};")[0]

                                    jj=js_chal.split("var ")[2].split("=")
                                    j_1=jj[0]
                                    j_12=jj[1].split(";")[0]

                                    jj=js_chal.split("var ")[3].split("=")
                                    j_2=jj[0]
                                    j_22=jj[1].split(";")[0]

                                    jj=js_chal.split("var ")[4].split("=")
                                    j_3=jj[0]
                                    j_32=jj[1].split(";")[0]

                                    jj=js_chal.split("var ")[5].split("=")

                                    j_4=jj[0]
                                    j_42=jj[1].split(";")[0]   

                                    jsin={"response":f"{{\"rf\":{{\"{j_1}\":{j_12},\"{j_2}\":{j_22},\"{j_3}\":{j_32},\"{j_4}\":{j_42}}},\"s\":\"{j_s}\"}}"}
                                    prej=jsin
                                except:
                                    jsin=prej


                                try:
                                    email_message=mm.recieve()
                                except Exception as exc:
                                    
                                        
                                    try:
                                        tor_g.remove(tor)
                                    except:
                                        pass

                                    if 'code' in str(exc):
                                        tor_g.append(tor)

                                    tor=[]
                                    raise Exception(f"recieve e400 {exc}")

                                subject=email_message.get('Subject')
                                h = email.header.decode_header(subject)
                                code, encoding = h[0]
                                try:
                                    code=code.decode(encoding)
                                except:
                                    pass
                                code=code.split(' ')[0]
                                #print(code)
                                xfg=0



                                #time.sleep(random.randint(4,8))

                                
                                while True:
                                    try:
                                        jin=jsin
                                        if False:
                                            while True:
                                                token,titid=solvecaptcha('https://twitter.com/i/flow/signup',head['user-agent'],'2CB16598-CB82-4CF7-B332-5990DB66F3AB',[True,False,True,False],proxystr=proxystr)
                                                #print(token)
                                                if token==None:
                                                    #raise Exception('TOO LONG CAPTCHA2 ERROR')
                                                    xfg+=1
                                                    pass
                                                elif token!=False:
                                                    break
                                                else:
                                                    xfg+=1

                                                if xfg>10:
                                                    print('dolgo')
                                                    raise Exception('TOO LONG CAPTCHA1 ERROR')
                                                    xfg=0
                                        elif True:
                                            titid=0

                                            
                                        else:
                                            titid=0
                                        #     token=solveman.solveman('2CB16598-CB82-4CF7-B332-5990DB66F3AB',
                                        #     #proxystr='185.130.226.44:11982'
                                        #     #proxystr='s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                        #     #proxystr='s1.op-proxy.com:25000:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                        #    # proxystr=random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'])
                                              #proxystr=proxystr
                                        #     #proxystr=None
                                        #     # #,ua=head['user-agent']
                                        #     ,ua=None
                                        #     ,pid=None
                                            
                                        #     )
                                            

                                            #token=get_token('2')


                                            #token=guru_token('2CB16598-CB82-4CF7-B332-5990DB66F3AB',proxystr,None,head['user-agent'])
                                            #print(token)
                                            pass


                                        
                                        #jin={"response":"{\"rf\":{\"c745cd715da09f6bf841ddfdc7631c3c1b3505a63591249cbd7ed8b9a09ceab5\":-29,\"a147ea454929c07e6e2fc527042661e445a5686633c71103727a9a40bdf0a093\":-1,\"ad5131ebc87025653fd9ca9c5d12adc248f1903e8d97f05b33db419fb9f05436\":28,\"a3f296f8de01ced8a822c73af4c7ce71bc7d6a653373917a50b43adbf92f0cd6\":40},\"s\":\"chXoyNvk8GIM2GcQJ92nxPjLBBsQywkhOjlp6xQMnSATAnvccnbtuZQPnWQLPWJyOGESQxeBSdIr-OqtITrVBKAlVlLKNMaMgN4bIr92JWgqWq_u4LzceXHhwEasroyOHffbOkHjSf7A4aib8BvDulYjxUXFUcNY4R7X_8gkcqfQx_e44Qw3LwYXiTCUaM2Cz4FpyG7EMqSxMPw-xO9zCkMxRsIvaFwk1JPTt99Qu3LteAluyG_5no7ewurcjnI5PFAL4c6idD5Bc8s8WuPRdfzM_h1FIim-6EWkpGaNXIw19NbJ_rsfFtRa-Sz3s8MDNqQPM-XrY-TGLENKRvwA8gAAAYW8QQUi\"}"}
                                        

                                        #{"flow_token":"g;167390064323565796:-1673900646360:A9IpymBUACzBzG6njQjeaguD:0","subtask_inputs":[{"subtask_id":"Signup","sign_up":{"js_instrumentation":{"response":"{\"rf\":{\"c745cd715da09f6bf841ddfdc7631c3c1b3505a63591249cbd7ed8b9a09ceab5\":-29,\"a147ea454929c07e6e2fc527042661e445a5686633c71103727a9a40bdf0a093\":-1,\"ad5131ebc87025653fd9ca9c5d12adc248f1903e8d97f05b33db419fb9f05436\":28,\"a3f296f8de01ced8a822c73af4c7ce71bc7d6a653373917a50b43adbf92f0cd6\":40},\"s\":\"chXoyNvk8GIM2GcQJ92nxPjLBBsQywkhOjlp6xQMnSATAnvccnbtuZQPnWQLPWJyOGESQxeBSdIr-OqtITrVBKAlVlLKNMaMgN4bIr92JWgqWq_u4LzceXHhwEasroyOHffbOkHjSf7A4aib8BvDulYjxUXFUcNY4R7X_8gkcqfQx_e44Qw3LwYXiTCUaM2Cz4FpyG7EMqSxMPw-xO9zCkMxRsIvaFwk1JPTt99Qu3LteAluyG_5no7ewurcjnI5PFAL4c6idD5Bc8s8WuPRdfzM_h1FIim-6EWkpGaNXIw19NbJ_rsfFtRa-Sz3s8MDNqQPM-XrY-TGLENKRvwA8gAAAYW8QQUi\"}"},"link":"email_next_link","name":"addaad","email":"w.il.sona.oha.r.a61@gmail.com","birthday":{"day":20,"month":12,"year":1972},"personalization_settings":{"allow_cookie_use":true,"allow_device_personalization":true,"allow_partnerships":true,"allow_ads_personalization":true}}},{"subtask_id":"SignupSettingsListEmailNonEU","settings_list":{"setting_responses":[{"key":"twitter_for_web","response_data":{"boolean_data":{"result":true}}}],"link":"next_link"}},{"subtask_id":"SignupReview","sign_up_review":{"link":"signup_with_email_next_link"}},{"subtask_id":"ArkoseEmail","web_modal":{"completion_deeplink":"twitter://onboarding/web_modal/next_link?access_token=49063c5b28ac29421.5522810205|r=eu-west-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|pk=2CB16598-CB82-4CF7-B332-5990DB66F3AB|at=40|sup=1|rid=12|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager","link":"signup_with_email_next_link"}},{"subtask_id":"EmailVerification","email_verification":{"code":"655121","email":"w.il.sona.oha.r.a61@gmail.com","link":"next_link"}}]}
                                        xcza=0
                                        while True:
                                            #   {"flow_token":    ,"subtask_inputs":[{"subtask_id":"Signup","sign_up":{    "link":"email_next_link","name":"asdawasdwa","email":"sd","birthday":{"year":2000,"month":2,"day":12},            "personalization_settings":{"allow_cookie_use":false,"allow_device_personalization":false,"allow_partnerships":false,"allow_ads_personalization":false}}},{"subtask_id":"SignupSettingsListEmail", "settings_list":{"setting_responses":[{"key":"allow_emails_about_activity","response_data":{"boolean_data":{"result":false}}},{"key":"find_by_email","response_data":{"boolean_data":{"result":false}}},{"key":"personalize_ads","response_data":{"boolean_data":{"result":false}}}],"link":"next_link"}},{"subtask_id":"SignupReview","sign_up_review":{"link":"signup_with_email_next_link"}},{"subtask_id":"ArkoseEmail","web_modal":{"completion_deeplink":"twitter://onboarding/web_modal/next_link?access_token=2291752cb2122b693.7064486905|r=eu-west-1|meta=3|meta_width=327|meta_height=500|metabgclr=transparent|metaiconclr=%23757575|guitextcolor=%23000000|pk=867D55F2-24FD-4C56-AB6D-589EDAF5E7C5|at=40|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager","link":"signup_with_email_next_link"}},{"subtask_id":"DidNotReceiveEmailDialog","menu_dialog":{"link":"cancel_link"}},{"subtask_id":"EmailVerification","email_verification":{"code":"123456","email":"sdasdawasd@gmail.com","link":"next_link"}}]}
                                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"Signup","sign_up":{"js_instrumentation":jin,"link":"email_next_link","name":name,"email":mail,"birthday":{"day":d1,"month":d2,"year":d3},"personalization_settings":{"allow_cookie_use":True,"allow_device_personalization":True,"allow_partnerships":True,"allow_ads_personalization":True}}},{"subtask_id":"SignupSettingsListEmailNonEU","settings_list":{"setting_responses":[{"key":"twitter_for_web","response_data":{"boolean_data":{"result":True}}}],"link":"next_link"}},{"subtask_id":"SignupReview","sign_up_review":{"link":"signup_with_email_next_link"}},{"subtask_id":"ArkoseEmail","web_modal":{"completion_deeplink":f"twitter://onboarding/web_modal/next_link?access_token={token}","link":"signup_with_email_next_link"}},{"subtask_id":"EmailVerification","email_verification":{"code":code,"email":mail,"link":"next_link"}}]}
                                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=30,json=pay,proxies=proxy)
                                            #r.close() 
                                            print(r)
                                            try:
                                                flow=r.json()['flow_token']
                                                if titid!=0:
                                                    fr=requests.get(f'http://2captcha.com/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=reportgood&id={titid}')
                                                    print(fr.text)
                                                break
                                            except:
                                                
                                                xcza+=1
                                                if "t complete your signup right now" in r.text or 't verify your email right now' in r.text:
                                                    pass
                                                else:
                                                    print(r.text,'sign_up')
                                                if xcza>2:
                                                    if "t complete your signup right now" in r.text or 't verify your email right now' in r.text:
                                                        try:
                                                            tor_g.remove(tor)
                                                        except:
                                                            pass
                                                        #tor_g[number_t]=tor
                                                        if False:
                                                            
                                                            
                                                            if writ==False:
                                                                with lock:
                                                                    with open(f'/root/work/create_and_unban_SYSTEM/{systemn}/hotc_clear.txt','a') as mim:
                                                                        mim.writelines(f"{MAIL}:{MPASS}\n")
                                                                        writ=True
                                                        else:
                                                            tor_g.append(tor)
                                                    else:
                                                        print(r.text,'AHUET CHTO')
                                                    # print(s.cookies.get_dict())
                                                    # print(head)
                                                    fer+=1
                                                    if titid!=0:
                                                        fr=requests.get(f'http://2captcha.com/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=reportbad&id={titid}')
                                                        print(fr.text)
                                                    raise Exception(f"sign_up e400 {r.text} {MAIL}")
                
                                        for i in r.headers:
                                            if 'csrf' in i:
                                                s.headers['x-csrf-token']=r.headers[i]
                                        #print('sign_up')

                                        
                                        #time.sleep(random.randint(4,8))

                                        return s,flow,mail,name,head,d1,d2,d3,ua,somer
                                        #break
                                    except Exception as zxcc:
                                        zxcxzc+=1
                                        try:
                                            s.close()
                                        except:
                                            pass

                                        if zxcxzc>1:
                                            raise Exception(zxcc)
                                        else:
                                            print(f'ERROR elon gandon {zxcc}')


                            except Exception as zxc:
                                raise Exception(zxc)
                            finally:
                                try:
                                    s.close()
                                except:
                                    pass
                    
                    def create_outlook():
                            try:
                                global tor_g
                                if False:
                                    totmn=input('mailshot{} - ')
                                    while True:
                                        with open(f'mailshot{totmn}.txt','r') as acpmm:
                                            acpmm=acpmm.readlines()
                                        mmm=True
                                        MG=False
                                        dess=':'
                                        if '|' in acpmm[0]:
                                            dess='|'
                                        MAIL=acpmm[0].split(dess)[0]
                                        
                                        MPASS=acpmm[0].split(dess)[1].replace('\n','')

                                        if '@gmx' in MAIL:
                                            typegh='gmx'
                                        elif '@gmail' in MAIL:
                                            typegh='gmail'
                                        elif '@outlook' in MAIL or '@hotmail' in MAIL:
                                            typegh='hot'
                                        elif '@mail' in MAIL:
                                            typegh='mail'
                                        elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                                            typegh='rambler'
                                        try:
                                            mm=mmail.mail_by_login(MAIL,MPASS,typegh)
                                            umail=urllib.parse.quote(MAIL)
                                            while True:
                                                ersins=ersin
                                                try:
                                                    check_mailr=s.get(f'https://api.twitter.com/i/users/email_available.json?email={umail}',proxies=proxy)
                                                    ersin=ersins
                                                    break
                                                except:
                                                    ersin+=1
                                                    #changecr()


                                            if check_mailr.json()['taken']==False and check_mailr.json()['valid']==True:
                                                print('good mail') 
                                            else:
                                                raise Exception('bad mail') 
                                            mail=MAIL
                                            break
                                        except Exception as x:
                                            print(repr(x))
                                            with lock:
                                                with open(f'mailshot{totmn}.txt','w') as acpmtw:
                                                    acpmtw.writelines(acpmm[1:])
                                            print('broken')
                                else:
                                    try:
                                        s=requests.session()
                                        retry = Retry(connect=3, backoff_factor=0.5)
                                        #adapter = HTTPAdapter(max_retries=retry)
                                        adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,max_retries=retry)
                                        s.mount('http://', adapter)
                                        s.mount('https://', adapter)
                                        #s.mount('https://', DESAdapter(max_retries=3))

                                        software_names = [SoftwareName.CHROME.value]
                                        operating_systems = [OperatingSystem.WINDOWS.value]   

                                        user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=1)
                                
                                        userAgent = user_agent_rotator.get_random_user_agent()
                                        userAgent=userAgent.replace(f"Chrome/{userAgent.split('Chrome/')[-1].split(' ')[0]}",f"Chrome/{randint(50,99)}.0.{randint(111,9999)}.{randint(1,99)}")
                                        userAgent=userAgent.replace(f"Safari/{userAgent.split('Safari/')[-1].split(' ')[0]}",f"Safari/{randint(100,999)}.{randint(1,99)}")
                                        userAgent=userAgent.replace(f"AppleWebKit/{userAgent.split('AppleWebKit/')[-1].split(' ')[0]}",f"AppleWebKit/{randint(100,999)}.{randint(1,99)}")
                                        userAgent=userAgent.replace(f"Windows NT {userAgent.split('Windows NT ')[0][:2]}",f"Windows NT {randint(1,9)}.{randint(1,9)}")
                                        uak=userAgent
                                        #uak=f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(92,111)}.0.0.0 Safari/537.36'
                                        uak=f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
                                        if False:
                                            print('begin')

                                            s.headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
                                            head={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'}
                                            #r=s.get('https://signup.live.com/signup',headers=head,proxies=proxy)
                                            r=s.get('https://outlook.live.com/owa/?nlp=1&signup=1',headers=head,timeout=15,proxies=proxy)

                                            print(r)
                                            print(r.headers)
                                            raise Exception()


                                            uid=s.cookies.get_dict()['uaid']
                                            mem=s.cookies.get_dict()['MSPRequ']

                                            ct=mem.split('=')[-2].split('&')[0]
                                            m_id=mem.split('=')[1].split('&')[0]
                                                #https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&checkda=1&ct=1674302984&rver=7.3.6960.0&wp=MBI_SSL&wreply=https%3A%2F%2Fsignup.live.com%2Fsignup%3Flcid%3D1033%26wa%3Dwsignin1.0%26rpsnv%3D13%26ct%3D1674302983%26rver%3D7.0.6737.0%26wp%3DMBI_SSL%26wreply%3Dhttps%253a%252f%252foutlook.live.com%252fowa%252f%253fnlp%253d1%2526signup%253d1%2526RpsCsrfState%253dafb70ecf-4cc7-e82e-9e2e-d3e0b13f9fdb%26id%3D292841%26CBCXT%3Dout%26lw%3D1%26fl%3Ddob%252cflname%252cwld%26cobrandid%3D90015%26lic%3D1%26uaid%3D6bc1dcd10b334136a8f49f33fcde777a&lc=1033&id=68692&pcexp=false&mkt=en-EN&uaid=6bc1dcd10b334136a8f49f33fcde777a
                                            gurl=f'https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&checkda=1&ct={str(time.time()).split(".")[0]}&rver=7.3.6960.0&wp=MBI_SSL&wreply=https%3A%2F%2Fsignup.live.com%2Fsignup%3Flic%3D1%26uaid%3D{uid}&lc=1033&id={m_id}&mkt=en-US&uaid={uid}'

                                            #gurl=f'https://signup.live.com/signup?lcid=1033&wa=wsignin1.0&rpsnv=13&ct={str(time.time()).split(".")[0]}&rver=7.0.6737.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1%26signup%3d1%26RpsCsrfState%3dafb70ecf-4cc7-e82e-9e2e-d3e0b13f9fdb&id=292841&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=90015&lic=1&uaid={uid}'

                                            r=s.get(gurl)


                                            print('new begin')
                                            r=s.get(f'https://signup.live.com/signup?lic=1&uaid={uid}',proxies=proxy)
                                            print(r)
                                        else:
                                            for ight in range(3):
                                                try:
                                                    print('begin')
                                                    
                                                    s.headers['User-Agent']=uak
                                                    head={'User-Agent': uak#,'Connection': 'close'
                                                    }
                                                    #r=s.get('https://signup.live.com/signup',headers=head,timeout=15,proxies=proxy)
                                                    r=s.get('https://outlook.live.com/owa/?nlp=1&signup=1',headers=head,timeout=5,proxies=proxy, allow_redirects=False)
                                                    #r.close() 
                                                    print('okay')

                                                    wreply=r.headers['location'].split('&wreply=')[-1].split('&id=')[0]
                                                    #print(wreply)

                                                    
                                                    locat=r.headers['location']
                                                    #print(locat)
                                                    
                                                    r=s.get(locat, allow_redirects=False,proxies=proxy,timeout=15)
                                                    #r.close() 
                                                    #print(r,1)
                                                
                                                    locat=r.headers['location']
                                                    #print(locat)
                                                    r=s.get(locat, allow_redirects=False,timeout=15
                                                    #,proxies=proxy
                                                    )
                                                    #r.close() 
                                                # print(r,2)
                                                    locat=r.headers['location']
                                                # print(locat)

                                                    wreply_full=locat.split('?')[-1]
                                                    break
                                                except Exception as zxc:
                                                    if ight>0:
                                                        raise Exception(zxc)
                                                
                                            #print(wreply_full)
                                        
                                            r=s.get(locat, allow_redirects=False,proxies=proxy
                                            ,timeout=15)

                                            #r.close() 
                                            #print(r,3)

                                            uid=s.cookies.get_dict()['uaid']
                                            mem=s.cookies.get_dict()['MSPRequ']
                                            #print(uid)
                                            ct=mem.split('=')[-2].split('&')[0]
                                            m_id=mem.split('=')[1].split('&')[0]



                                            # input('?')

                                            # gurl=f'https://signup.live.com/signup?lcid=1033&wa=wsignin1.0&rpsnv=13&ct={str(time.time()).split(".")[0]}&rver=7.0.6737.0&wp=MBI_SSL&wreply={wreply}&id=292841&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=90015&lic=1&uaid={uid}'

                                            # r=s.get(gurl)


                                            # print('new begin')
                                            # r=s.get(f'https://signup.live.com/signup?lic=1&uaid={uid}',proxies=proxy)
                                            # print(r)

                                            #raise Exception()

                                        tow=r.text.split('var t0=')[-1].split('"};')[0]

                                        canary=tow.split('"apiCanary":"')[-1].split('","ip"')[0]
                                        tcxt=tow.split('"tcxt":"')[-1].split('"},"WLXAccount"')[0]

                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')




                                        key=r.text.split('var Key="')[-1].split('"; var randomNum')[0]
                                        random_num=r.text.split('var randomNum="')[-1].split('"; var')[0]
                                        fid=r.text.split('"fid":"')[-1].split('","')[0]
                                        ski=r.text.split('var SKI="')[-1].split('";</script>')[0]


                                        head['tcxt']=tcxt
                                        head['canary']=canary
                                        head['uaid']=uid
                                        #print(head)
                                                                                                                                        #1674293340956.4908
                                        #print('start zalupniy event')
                                        timestart=str(time.time())
                                        timestart=int(timestart.split('.')[0]+timestart.split('.')[1][0:3])                             #1674283653639
                                        pay={"evts":[{"perf":{"data":{"navigation":{"type":0,"redirectCount":0},"timing":{"connectStart":timestart,"navigationStart":timestart+1,"secureConnectionStart":0,"fetchStart":timestart,"domContentLoadedEventStart":timestart+1,"responseStart":timestart,"domInteractive":timestart+1,"domainLookupEnd":timestart,"responseEnd":timestart+90,"redirectStart":0,"requestStart":1674283653640,"unloadEventEnd":0,"unloadEventStart":0,"domLoading":timestart,"domComplete":timestart,"domainLookupStart":timestart,"loadEventStart":timestart,"domContentLoadedEventEnd":timestart,"loadEventEnd":timestart+1,"redirectEnd":0,"connectEnd":timestart,"customLoadEventEnd":timestart},"entries":[{"name":f"https://signup.live.com/signup\u003Flic=1&uaid={uid}","entryType":"navigation","startTime":0,"duration":1845.5999999046326,"initiatorType":"navigation","nextHopProtocol":"h2","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,

                                        "fetchStart":857.3999999761581,"domainLookupStart":857.3999999761581,"domainLookupEnd":857.3999999761581,"connectStart":857.3999999761581,"connectEnd":857.3999999761581,"secureConnectionStart":857.3999999761581,"requestStart":858.2999999523163,"responseStart":1271.5,"responseEnd":1361.5999999046326,"transferSize":67207,"encodedBodySize":66907,"decodedBodySize":209220,"responseStatus":0,"serverTiming":[],"unloadEventStart":0,"unloadEventEnd":0,"domInteractive":1720.2999999523163,"domContentLoadedEventStart":1720.2999999523163,"domContentLoadedEventEnd":1794.0999999046326,"domComplete":1844.0999999046326,"loadEventStart":1844.2999999523163,"loadEventEnd":1845.5999999046326,"type":"navigate","redirectCount":0,"activationStart":0},{"name":"https://acctcdn.msftauth.net/converged_ux_v2_nBE5FSqn9KpH44ZlTc3VqQ2.css\u003Fv=1","entryType":"resource","startTime":1337.8999999761581,"duration":281.39999997615814,"initiatorType":"link","nextHopProtocol":"","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1337.8999999761581,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1619.2999999523163,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/jqueryshim_hlu0tTfjWJFWYNt1WZrVqg2.js\u003Fv=1","entryType":"resource","startTime":1338.1999999284744,"duration":240.39999997615814,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,
                                        "redirectEnd":0,"fetchStart":1338.1999999284744,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1578.5999999046326,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/knockout_3.3.0_X1BYS2jZMbi7hfUj8VuqFA2.js\u003Fv=1","entryType":"resource","startTime":1339.6999999284744,"duration":209.20000004768372,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1339.6999999284744,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1548.8999999761581,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/lwsignupstringscountrybirthdate_ru-ru_QILgfz_rxYdNh-eBH6QJZQ2.js\u003Fv=1","entryType":"resource","startTime":1340,"duration":281.2999999523163,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1340,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1621.2999999523163,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/lightweightsignuppackage_JJwKyIbcoS3piKuour0v0Q2.js\u003Fv=1","entryType":"resource",
                                        "startTime":1340.3999999761581,"duration":270.60000002384186,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1340.3999999761581,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1611,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/images/microsoft_logo_7lyNn7YkjJOP0NwZNw6QvQ2.svg","entryType":"resource","startTime":1340.6999999284744,"duration":457.60000002384186,"initiatorType":"img","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1340.6999999284744,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1798.2999999523163,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":0,"serverTiming":[]},{"name":"first-paint","entryType":"paint","startTime":1668.0999999046326,"duration":0},{"name":"first-contentful-paint","entryType":"paint","startTime":1719.8999999761581,"duration":0},{"name":"https://acctcdn.msftauth.net/images/dropdown_caret_KXSZjGsyILZaoTf0sI9X-A2.svg","entryType":"resource","startTime":1793.8999999761581,"duration":45,"initiatorType":"img","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1793.8999999761581,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,
                                        "requestStart":0,"responseStart":0,"responseEnd":1838.8999999761581,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":0,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/oneds_CBxZrnSxLbjHuOGn7pHqpg2.js\u003Fv=1","entryType":"resource","startTime":1845,"duration":74.09999990463257,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1845,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1919.0999999046326,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":0,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/images/2_vD0yppaJX3jBnfbHF1hqXQ2.svg","entryType":"resource","startTime":1846.1999999284744,"duration":56.60000002384186,"initiatorType":"css","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1846.1999999284744,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1902.7999999523163,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":0,"serverTiming":[]},{"name":"https://signup.live.com/Resources/images/microsoft_logo_7lyNn7YkjJOP0NwZNw6QvQ2.svg",
                                        "entryType":"resource","startTime":1848.5,"duration":160.29999995231628,"initiatorType":"link","nextHopProtocol":"h2","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1848.5,"domainLookupStart":1848.5,"domainLookupEnd":1848.5,"connectStart":1848.5,"connectEnd":1848.5,"secureConnectionStart":1848.5,"requestStart":1852.1999999284744,"responseStart":2007.8999999761581,"responseEnd":2008.7999999523163,"transferSize":1764,"encodedBodySize":1464,"decodedBodySize":3651,"responseStatus":200,"serverTiming":[]},{"name":"https://signup.live.com/Resources/images/favicon.ico","entryType":"resource","startTime":1849.1999999284744,"duration":159.30000007152557,"initiatorType":"link","nextHopProtocol":"h2","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1849.1999999284744,"domainLookupStart":1849.1999999284744,"domainLookupEnd":1849.1999999284744,"connectStart":1849.1999999284744,"connectEnd":1849.1999999284744,"secureConnectionStart":1849.1999999284744,"requestStart":1853.1999999284744,"responseStart":2004.5,"responseEnd":2008.5,"transferSize":17474,"encodedBodySize":17174,"decodedBodySize":17174,"responseStatus":200,"serverTiming":[]},{"name":"https://signup.live.com/Resources/images/2_vD0yppaJX3jBnfbHF1hqXQ2.svg","entryType":"resource","startTime":1851.1999999284744,"duration":222.60000002384186,"initiatorType":"link","nextHopProtocol":"h2","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1851.1999999284744,"domainLookupStart":1851.1999999284744,"domainLookupEnd":1851.1999999284744,
                                        "connectStart":1851.1999999284744,"connectEnd":1851.1999999284744,"secureConnectionStart":1851.1999999284744,"requestStart":1853.3999999761581,"responseStart":2073.1999999284744,"responseEnd":2073.7999999523163,"transferSize":2164,"encodedBodySize":1864,"decodedBodySize":1864,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/datarequestpackage_h-_7C7UzwdefXJT9njDBTQ2.js","entryType":"resource","startTime":1856.3999999761581,"duration":47.699999928474426,"initiatorType":"script","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1856.3999999761581,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1904.0999999046326,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":200,"serverTiming":[]},{"name":"https://acctcdn.msftauth.net/images/favicon.ico\u003Fv=2","entryType":"resource",
                                        "startTime":1857.5999999046326,"duration":85.60000002384186,"initiatorType":"other","nextHopProtocol":"","renderBlockingStatus":"non-blocking","workerStart":0,"redirectStart":0,"redirectEnd":0,"fetchStart":1857.5999999046326,"domainLookupStart":0,"domainLookupEnd":0,"connectStart":0,"connectEnd":0,"secureConnectionStart":0,"requestStart":0,"responseStart":0,"responseEnd":1943.1999999284744,"transferSize":0,"encodedBodySize":0,"decodedBodySize":0,"responseStatus":0,"serverTiming":[]}],"connection":{"onchange":None,"effectiveType":"4g","rtt":50,"downlink":1.45,"saveData":False}},"tm":2400.10009765625}}],"cm":{"uiflvr":1001,"scid":100118,"hpgid":200225,"tcxt":tcxt,"uaid":uid,"cntry":"EN","svr":{"dc":"EUS","ri":"WUSXXXX005C","ver":{"v":[2,0,2720,0]},"rt":"2023-01-21T06:47:33","et":62},"hst":"signup.live.com","nt":"4g","av":None},"tm":2404.10009765625}


                                        r=s.post('https://signup.live.com/API/ClientEvents',json=pay,headers=head,timeout=15,proxies=proxy)

                                        #r.close() 
                                        #print(r)

                                        tcxt=r.json()['cm']['tcxt']
                                        canary=r.json()['cm']['api']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt




                                        #print('event 1')
                                        pay={"pageApiId":200639,"clientDetails":[],"country":"EN","userAction":"","source":"PageView","clientTelemetryData":{"category":"PageLoad","pageName":"200639","eventInfo":{"timestamp":timestart+2,"enforcementSessionToken":None,"perceivedPlt":2400,"networkLatency":1362,"appVersion":None,"networkType":None,"precaching":None,"bundleVersion":None,"deviceYear":None,"isMaster":None,"bundleHits":None,"bundleMisses":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":uid,"scid":100118,"hpgid":200639}
                                            
                                        #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)

                                        #r.close() 
                                        #print(r)


                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt



                                        #print('Check name')
                                        sgh=0
                                        while True:
                                            try:
                                                r=requests.post('https://rustxt.ru/api/index.php',data={"method":"getNickName",
                                                        "count_result":1,
                                                        "len_nick_min":9,
                                                        "len_nick_max":12})
                                                MAIL=r.json()[0]
                                            except Exception as x:
                                                try:
                                                    r=requests.get('https://api.randomdatatools.ru/?typeName=all&unescaped=false').json()
                                                    MAIL=r['login']+''.join(random.choices(string.ascii_letters, k=randint(1,4)))
                                                except:
                                                    MAIL=''.join(random.choices(string.ascii_letters, k=randint(9,12)))


                                            if default==False:
                                                ll=''
                                                for i in MAIL:
                                                    if randint(0,100)>85:
                                                        i=i.capitalize()
                                                    ll+=i
                                                MAIL=ll  

                                                
                                                desr=random.choice(['_','__'])
                                                if desr=='|':
                                                    desr=random.choice([' ',''])+desr+random.choice([' ',''])

                                                tord=[]
                                                lr=''
                                                lrd=['eth','sol','gym','master','infl','crypto','nft','games','solana','rtx','beast','hyper','first','eco','forward','lgbt','extra','lucky','boss','genius']


                                                if randint(1,100)>50:

                                                    if randint(1,100)>35:
                                                        tord.append(randint(0,100))

                                                        if randint(0,100)>2:
                                                            lr=desr+lr

                                                    if randint(1,100)>75:
                                                        
                                                        lr=random.choice(lrd)

                                                        rgt=randint(1,100)
                                                        if rgt>70:
                                                            lr=lr.capitalize()
                                                        elif rgt>50:
                                                            lr=lr[0].capitalize()+lr[1:]

                                                        lr=desr+lr
                                                        tord.append(lr)


                                                    if randint(1,100)>75:
                                                        try:
                                                            lrd.remove(lr)
                                                        except:
                                                            pass
                                                        lr=random.choice(lrd)

                                                        rgt=randint(1,100)
                                                        if rgt>70:
                                                            lr=lr.capitalize()
                                                        elif rgt>50:
                                                            lr=lr[0].capitalize()+lr[1:]

                                                        lr=desr+lr
                                                        tord.append(lr)


                                                    random.shuffle(tord)

                                                    for ing in tord:
                                                        MAIL+=str(ing)    

                                            do=random.choice(['hotmail','outlook'])

                                            pay={"signInName":f"{MAIL}@{do}.com","uaid":uid,"includeSuggestions":True,"uiflvr":1001,"scid":100118,"hpgid":200639}
                                            #r=s.post(f'https://signup.live.com/API/CheckAvailableSigninNames?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                            r=s.post(f'https://signup.live.com/API/CheckAvailableSigninNames?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)
                                            #r.close() 
                                            try:
                                                if r.json()['isAvailable']==True:
                                                    break
                                                else:
                                                    print(r.json())
                                            except:
                                                sgh+=1
                                                if sgh>2:
                                                    raise Exception(r.text)
                                                time.sleep(0.2)

                                        #print(r)

                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt



                                        #print('event 2')
                                        pay={"pageApiId":200646,"clientDetails":[{"apiId":200197,"success":True,"time":0}],"country":"EN","userAction":"","source":"PageView","clientTelemetryData":{"category":"PageView","pageName":"200646","eventInfo":{"timestamp":timestart+3,"enforcementSessionToken":None,"appVersion":None,"networkType":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":uid,"scid":100118,"hpgid":200646}

                                        #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)

                                        #r.close() 
                                        #print(r)


                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt


                                        #print('event 3')
                                        pay={"pageApiId":200640,"clientDetails":[],"country":"EN","userAction":"Action_ClientSideTelemetry","source":"PageView","clientTelemetryData":{"category":"PageView","pageName":"200640","eventInfo":{"timestamp":timestart+4,"enforcementSessionToken":None,"appVersion":None,"networkType":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":"a3399fa2272f40bb944b5cb71937a966","scid":100118,"hpgid":200640}
                                        #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)

                                        #r.close() 
                                        #print(r)


                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt


                                        dc=False
                                        #print('event 4')
                                        pay={"pageApiId":200650,"clientDetails":[],"country":"EN","userAction":"Action_ClientSideTelemetry","source":"PageView","clientTelemetryData":{"category":"PageView","pageName":"200650","eventInfo":{"timestamp":timestart+4,"enforcementSessionToken":None,"appVersion":None,"networkType":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":uid,"scid":100118,"hpgid":200650}
                                        #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        #r.close() 
                                        #print(r)


                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt


                                        dt = datetime.datetime.now()
                                        value = datetime.datetime.fromtimestamp(time.mktime(dt.timetuple()))
                                        rts=f"{value.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"


                                        MPASS=''.join(random.choices(string.ascii_uppercase + string.digits, k=8))+str(random.randint(1,19))
                                        cipher=requests.get(f'http://127.0.0.1:3000/getcipher?password={MPASS}&Key={key}&randomNum={random_num}').text

                                        #print('CREATE HAHAHA') #"2023-01-21T10:25:05.669Z"
                                        # name='otebuis'
                                        # lname='putin'
                                        try:
                                            try:
                                                r=requests.get('https://api.randomdatatools.ru/?typeName=all&unescaped=false',timeout=2).json()
                                                name=r['FirstName']
                                                lname=r['LastName']
                                                name=translit(name, 'ru', reversed=True)
                                                lname=translit(lname, 'ru', reversed=True)
                                                
                                            except Exception as x:
                                                print('namefake',repr(x))
                                                rr=requests.get('https://api.namefake.com/',timeout=2)
                                                rr=rr.json()['name'].split(' ')
                                                name=rr[0]
                                                lname=rr[1]
                                        except:
                                            name=''.join(random.choices(string.ascii_letters , k=randint(9,12)))
                                            lname=''.join(random.choices(string.ascii_letters , k=randint(9,12)))

                                        birth=f"{random.randint(1,25)}:0{random.randint(1,9)}:{random.randint(1990,2000)}"

                                        #print(name)
                                            #{"RequestTimeStamp":,"MemberName":,                    "CheckAvailStateMap":["@outlook.com:undefined"],"EvictionWarningShown":[],"UpgradeFlowToken":{},"FirstName":"asadaa","LastName":"adwdasdaw","MemberNameChangeCount":1,"MemberNameAvailableCount":1,"MemberNameUnavailableCount":0,"CipherValue":,"SKI":"","BirthDate":"    ","Country":"UA","IsOptOutEmailDefault":true,"IsOptOutEmailShown":true,"IsOptOutEmail":true,"LW":true,"SiteId":"292841","IsRDM":0,"WReply":     ,"ReturnUrl":null,"SignupReturnUrl":null,"uiflvr":1001,"uaid":"a5,"SuggestedAccountType":"OUTLOOK","SuggestionType":"Locked","HFId":"","encAttemptToken":"","dfpRequestId":"","scid":100118,"hpgid":200650}
                                        if True:
                                            siteid='292841'
                                        else:
                                            siteid='68692'
                                        
                                        pay={"RequestTimeStamp":rts,"MemberName":f"{MAIL}@{do}.com","CheckAvailStateMap":[f"{MAIL}@{do}.com:undefined"],"EvictionWarningShown":[],"UpgradeFlowToken":{},"FirstName":name,"LastName":lname,"MemberNameChangeCount":1,"MemberNameAvailableCount":1,"MemberNameUnavailableCount":0,"CipherValue":cipher,"SKI":ski,"BirthDate":birth,"Country":"EN","IsOptOutEmailDefault":True,"IsOptOutEmailShown":True,"IsOptOutEmail":True,"LW":True,"SiteId":siteid,"IsRDM":0,"WReply":wreply,"ReturnUrl":None,"SignupReturnUrl":None,"uiflvr":1001,"uaid":uid,"SuggestedAccountType":"EASI","SuggestionType":"Prefer","HFId":fid,"encAttemptToken":"","dfpRequestId":"","scid":100118,"hpgid":200650}
                                        rc=s.post(f'https://signup.live.com/API/CreateAccount?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)

                                        #print(rc)


                                    

                                        
                                            
                                        print('event 5')
                                        pay={"pageApiId":201040,"clientDetails":[{"apiId":200050,"errorCode":"1041","success":False,"time":0}],"country":"EN","userAction":"","source":"PageView","clientTelemetryData":{"category":"PageView","pageName":"201040","eventInfo":{"timestamp":timestart+6,"enforcementSessionToken":None,"appVersion":None,"networkType":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":uid,"scid":100118,"hpgid":201040}
                                        #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)
                                        
                                        #r.close() 
                                        #print(r)
                                        tcxt=r.json()['telemetryContext']
                                        canary=r.json()['apiCanary']
                                        canary=canary.encode('utf-8').decode('unicode-escape')
                                        tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                        head['canary']=canary
                                        head['tcxt']=tcxt





                                        #print('CREATE 2 HAHAHA') 
                                        asdf=0
                                        global er
                                        while True:


                                            asdf+=1
                                            if 'encAttemptToken' in rc.text:
                                                encAttemptToken=rc.json()['error']['data'].split('"encAttemptToken":"')[-1].split(r'",')[0].encode('utf-8').decode('unicode-escape')

                                            if 'dfpRequestId' in rc.text:    
                                                dfpRequestId=rc.json()['error']['data'].split('dfpRequestId":"')[-1].split('"')[0].encode('utf-8').decode('unicode-escape')
                                            if 'telemetryContext' in rc.text:
                                                tcxt=rc.json()['error']['telemetryContext']
                                                tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                                head['tcxt']=tcxt
                                            if '"fid":"' in rc.text:
                                                fid=rc.json()['error']['data'].split('fid":"')[-1].split('"')[0].encode('utf-8').decode('unicode-escape')
                                                
                                            xfg=0
                                            hiptoken='def'
                                            if dc:
                                                r=s.get(f'https://client.hip.live.com/GetHIP/GetHIPAMFE/HIPAMFE?id=15041&mkt=en-EN&fid={fid}&type=visual&rand=691960811')
                                                hiptoken=r.text.split('"hipToken":"')[-1].split('"')[0]
                                                
                                            
                                                response=s.get(f'https://{hiptoken.split(".")[0]}.client.hip.live.com/GetHIPData?hid={hiptoken}&fid={fid}&id=15041&type=visual&cs=HIPAMFE',stream=True)
                                                
                                                im64=base64.b64encode(r.content)
                                                im64=im64.decode("utf-8")
                                                #print(im64)
                                                
                                                with open(f'tmppicsxevil/{hiptoken}.jpg', 'wb') as out_file:
                                                    shutil.copyfileobj(response.raw, out_file)

                                                del response
                                            
                                            if dc:
                                                if False:
                                                    while True:
                                                        #print('NU BLYAT')
                                                        token,titid=solvecaptcha(f'https://signup.live.com/signup?{wreply_full}',uak,'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA',[True,False,False,False],proxystr=proxystr,typed=hiptoken)
                                                        print(token)
                                                        if token==None:
                                                            #raise Exception('TOO LONG CAPTCHA2 ERROR')
                                                            pass
                                                        elif token!=False:
                                                            break
                                                        else:
                                                            xfg+=1
                                                        if xfg==15:
                                                            raise Exception('TOO LONG CAPTCHA1 ERROR')
                                                            xfg=0
                                                else:

                                                    data = {'key': 'p0zQFrFTZ17uDmsH8x0LzN2bjyT8pHYG'}
                                                    mgm=open(f'tmppicsxevil/{hiptoken}.jpg', 'rb')
                                                    filed = {'file': mgm, 'submit': 'Upload and get the ID'}
                                                    r = requests.post(f'http://83.220.173.239:20875/in.php',data=data,files=filed)
                                                    mgm.close()
                                                    #print(r.text)
                                                    ref = r.text.split('|')[-1]
                                                    titid=ref
                                                    while True:
                                                        
                                                        result = requests.get(f'http://83.220.173.239:20875/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=get&id={ref}')
                                                        res = result.text.split('|')[-1]
                                                        if 'CAPCHA_NOT_READY' not in res:
                                                            token=res
                                                            print(token)
                                                            break
                                                        time.sleep(0.5)
                                                    try:
                                                        os.remove(f'tmppicsxevil/{hiptoken}.jpg')
                                                    except:
                                                        pass
                                            else:
                                                titid=0
                                                
                                                #token=get_token('1')


                                                # token=guru_token('B7D8911C-5CC8-A9A3-35B0-554ACEE604DA',
                                                # #proxystr
                                                # #'s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                                # #'s1.op-proxy.com:25000:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                                # #'185.130.226.44:11982'
                                                # #'pproxy.space:15235:eSAg3e:YmYgEPYD6Um3'
                                                # random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'])
                                                # ,proxy_id,uak)

                                                
                                                token=solveman.solveman('B7D8911C-5CC8-A9A3-35B0-554ACEE604DA',
                                                    #proxystr='185.130.226.44:11982'
                                                    #proxystr='s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                                    #proxystr='93.190.142.57:36649:843593e9-1229067:8oue5bctta'
                                                    #proxystr='43.131.38.59:2333:u26wtnbwq0a:a48487d621b8ef119136f49fdf2137b9'
                                                    
                                                    proxystr='s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                                                    #proxystr=random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','s1.op-proxy.com:31002:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'])
                                                    #proxystr=random.choice(['s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH','pproxy.space:15235:eSAg3e:YmYgEPYD6Um3'])
                                                    
                                                    #proxystr=proxystr
                                                    #proxystr=None
                                                    #proxystr='pproxy.space:15235:eSAg3e:YmYgEPYD6Um3'
                                                    # #,ua=head['user-agent']
                                                    ,ua=None
                                                    ,pid=None
                                                    
                                                    )
                                               
                                            if dc:
                                                #print('event 6')
                                                pay={"pageApiId":201040,"clientDetails":[],"country":"EN","userAction":"Action_LoadEnforcement,Action_ClientSideTelemetry","source":"UserAction","clientTelemetryData":{"category":"UserAction","pageName":"201040","eventInfo":{"timestamp":timestart+6,"enforcementSessionToken":token,"appVersion":None,"networkType":None}},"cxhFunctionRes":None,"netId":None,"uiflvr":1001,"uaid":uid,"scid":100118,"hpgid":201040}
                                                #r=s.post(f'https://signup.live.com/API/ReportClientEvent?lic=1&uaid={uid}',json=pay,headers=head,timeout=15,proxies=proxy)
                                                r=s.post(f'https://signup.live.com/API/ReportClientEvent?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)
                                                #r.close() 
                                                #print(r)
                                                tcxt=r.json()['telemetryContext']
                                                canary=r.json()['apiCanary']
                                                canary=canary.encode('utf-8').decode('unicode-escape')
                                                tcxt=tcxt.encode('utf-8').decode('unicode-escape')
                                                head['canary']=canary
                                                head['tcxt']=tcxt      
                                                    
                                                    
                                            if dc==False:                                                                                                                                                                                                                                                                                                                                                                                                                                                                        #"https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1%26signup%3d1%26RpsCsrfState%3de09e0b7f-118c-c351-cf1a-8bfa908e9fec"
                                                pay={"RequestTimeStamp":rts,"MemberName":f"{MAIL}@{do}.com","CheckAvailStateMap":[f"{MAIL}@{do}.com:undefined"],"EvictionWarningShown":[],"UpgradeFlowToken":{},"FirstName":name,"LastName":lname,"MemberNameChangeCount":1,"MemberNameAvailableCount":1,"MemberNameUnavailableCount":0,"CipherValue":cipher,"SKI":ski, "BirthDate":birth,"Country":"EN","IsOptOutEmailDefault":True,"IsOptOutEmailShown":True,"IsOptOutEmail":True,"LW":True,"SiteId":"292841","IsRDM":0,"WReply":wreply,"ReturnUrl":None,"SignupReturnUrl":None,"uiflvr":1001,"uaid":uid,"SuggestedAccountType": do.upper(),"SuggestionType":"Locked","HFId":fid,"HType":"enforcement","HSol":token,"HPId":"B7D8911C-5CC8-A9A3-35B0-554ACEE604DA","encAttemptToken":encAttemptToken,"dfpRequestId":dfpRequestId,"scid":100118,"hpgid":201040}
                                            
                                            
                                            #pay={"RequestTimeStamp":rts,"MemberName":f"{MAIL}@{do}.com","CheckAvailStateMap":[f"{MAIL}@{do}.com:undefined"],"EvictionWarningShown":[],"UpgradeFlowToken":{},"FirstName":name,"LastName":lname,"MemberNameChangeCount":1,"MemberNameAvailableCount":1,"MemberNameUnavailableCount":0,"CipherValue":cipher,"SKI":ski,"BirthDate":birth,"Country":"EN","IsOptOutEmailDefault":True,"IsOptOutEmailShown":True,"IsOptOutEmail":True,"LW":True,"SiteId":"68692","IsRDM":0,"WReply":None,"ReturnUrl":None,"SignupReturnUrl":None,"uiflvr":1001,"uaid":uid,"SuggestedAccountType":"EASI","SuggestionType":"Prefer","HFId":fid,"encAttemptToken":"","dfpRequestId":"","scid":100118,"hpgid":200650}
                                            
                                            else:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            #15041                                    
                                                pay={"RequestTimeStamp":rts,"MemberName":f"{MAIL}@{do}.com","CheckAvailStateMap":[f"{MAIL}@{do}.com:undefined"],"EvictionWarningShown":[],"UpgradeFlowToken":{},"FirstName":name,"LastName":lname,"MemberNameChangeCount":1,"MemberNameAvailableCount":1,"MemberNameUnavailableCount":0,"CipherValue":cipher,"SKI":ski, "BirthDate":birth,"Country":"EN","IsOptOutEmailDefault":True,"IsOptOutEmailShown":True,"IsOptOutEmail":True,"LW":True,"SiteId":"292841","IsRDM":0,"WReply":wreply,"ReturnUrl":None,"SignupReturnUrl":None,"uiflvr":1001,"uaid":uid,"SuggestedAccountType": do.upper(),"SuggestionType":"Locked","HFId":fid,"HType":"visual",'HSId': '15041','HId':hiptoken,"HSol":token,"encAttemptToken":encAttemptToken,"dfpRequestId":dfpRequestId,"scid":100118,"hpgid":200644}
                                            print('gogog')
                                            rc=s.post(f'https://signup.live.com/API/CreateAccount?{wreply_full}',json=pay,headers=head,timeout=15,proxies=proxy)
                                            
                                            if('signinName' in rc.text):
                                                #Ipop
                                                print('ipop')
                                                if titid!=0:
                                                    fr=requests.get(f'http://2captcha.com/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=reportgood&id={titid}')
                                                break
                                            else:
                                                if r'"dc":"' not in rc.text:
                                                    dc=True
                                                    if titid!=0:
                                                        fr=requests.get(f'http://2captcha.com/res.php?key=2be1c39bb553365d0c09f37b96bca7ac&action=reportbad&id={titid}')
                                                    #print(fr.text)
                                                else:
                                                    dc=False
                                                print(rc.text,hiptoken)
                                                er+=1

                                                print('ERROR outlook again')
                                                if asdf>0:
                                                    raise Exception('AGAIn')

                                        #print('Account Created! Enabling IPOP')
                                        for ddds in range(5):
                                            try:
                                                headers = {
                                                    'Host': 'login.live.com',
                                                    'User-Agent': uak,
                                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                                                    'Accept-Language': 'en-US,en;q=0.5',
                                                    'Referer': 'https://signup.live.com/',
                                                    'Content-Type': 'application/x-www-form-urlencoded',
                                                    'Origin': 'https://signup.live.com',
                                                    'Upgrade-Insecure-Requests': '1',
                                                    'Sec-Fetch-Dest': 'document',
                                                    'Sec-Fetch-Mode': 'navigate',
                                                    'Sec-Fetch-Site': 'same-site',
                                                    #'Connection': 'close',
                                                }

                                                data = f'slt={rc.json()["slt"]}'

                                                redirectURL = rc.json()['redirectUrl']

                                                response = s.post(
                                                    redirectURL,
                                                    headers=headers,
                                                    data=data,
                                                    #proxies=proxy
                                                )

                                                print('Account Created! Enabling IPOP (1)')

                                                urlPost = response.text.split('urlPost:\'')[1].split('\',')[0]

                                                #print(urlPost)

                                                headers['Referer'] = redirectURL

                                                sFT = response.text.split('sFT:\'')[1].split('\',')[0]

                                                #print(sFT)

                                                data = f'LoginOptions=3&type=28&ctx=&hpgrequestid=&PPFT={sFT}&i19=1526'

                                                headers = {
                                                    'Host': 'login.live.com',
                                                    'User-Agent': uak,
                                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                                                    'Accept-Language': 'en-US,en;q=0.5',
                                                    'Referer': redirectURL,
                                                    'Content-Type': 'application/x-www-form-urlencoded',
                                                    'Origin': 'https://login.live.com',
                                                    'Upgrade-Insecure-Requests': '1',
                                                    'Sec-Fetch-Dest': 'document',
                                                    'Sec-Fetch-Mode': 'navigate',
                                                    'Sec-Fetch-Site': 'same-origin',
                                                    'Sec-Fetch-User': '?1',
                                                    #'Connection': 'close',
                                                }

                                                response = s.post(
                                                    urlPost,
                                                    headers=headers,
                                                    data=data,
                                                    #proxies=proxy,
                                                    timeout=15
                                                )

                                                print('Account Created! Enabling IPOP (2)')

                                                #print(response.text)

                                                html = BeautifulSoup(response.text, 'html.parser')

                                                fmHF = html.find('form', {'id': 'fmHF'}).get('action')

                                                try:
                                                    wbids = html.find('input', {'id': 'wbids'}).get('value')
                                                except:
                                                    wbids = False
                                                try:
                                                    pprid = html.find('input', {'id': 'pprid'}).get('value')
                                                except:
                                                    pprid = False
                                                try:
                                                    wbid = html.find('input', {'id': 'wbid'}).get('value')
                                                except:
                                                    wbid = False
                                                NAP = html.find('input', {'id': 'NAP'}).get('value')
                                                ANON = html.find('input', {'id': 'ANON'}).get('value')
                                                t = html.find('input', {'id': 't'}).get('value')

                                                headers = {
                                                    'Host': 'outlook.live.com',
                                                    'User-Agent': uak,
                                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                                                    'Accept-Language': 'en-US,en;q=0.5',
                                                    'Referer': 'https://login.live.com/',
                                                    'Origin': 'https://login.live.com',
                                                    'Upgrade-Insecure-Requests': '1',
                                                    'Sec-Fetch-Dest': 'document',
                                                    'Sec-Fetch-Mode': 'navigate',
                                                    'Sec-Fetch-Site': 'same-site',
                                                }
                                                data = {
                                                    'NAP': NAP,
                                                    'ANON': ANON,
                                                    't': t,
                                                }
                                                if(wbids != False):
                                                    data['wbids'] = wbids
                                                    
                                                if(pprid != False):
                                                    data['pprid'] = pprid
                                                    
                                                if(wbid != False):
                                                    data['wbid'] = wbid

                                                try:
                                                    response = s.post(fmHF, headers=headers, data=data, proxies=proxy
                                                    ,timeout=20)

                                                    print('Account Created! Enabling IPOP (3)')

                                                
                                                    raise Exception('done')
                                                    headers = {
                                                        'Host': 'outlook.live.com',
                                                        'User-Agent': uak,
                                                        'Accept': '*/*',
                                                        'Accept-Language': 'en-US,en;q=0.5',
                                                        'Referer': 'https://outlook.live.com/',
                                                        'Sec-Fetch-Dest': 'empty',
                                                        'Sec-Fetch-Mode': 'cors',
                                                        'Sec-Fetch-Site': 'same-origin',
                                                    }

                                                    params = {
                                                        'nojit': '1',
                                                    }

                                                    response = s.get('https://outlook.live.com/owa/0/', params=params,headers=headers,timeout=15, proxies=proxy, allow_redirects=False)
                                                
                                                    #print('Account Created! Enabling IPOP (4)')

                                                    #print(response.text, response.status_code)

                                                    headers = {
                                                        'Host': 'outlook.live.com',
                                                        'User-Agent': uak,
                                                        'Accept': '*/*',
                                                        'Accept-Language': 'en-US,en;q=0.5',
                                                        'Referer': 'https://outlook.live.com/',
                                                        'Action': 'SetConsumerMailbox',
                                                        'Content-Type': 'application/json; charset=utf-8',
                                                        'X-Owa-Canary': response.cookies.get_dict()['X-OWA-CANARY'],
                                                        'X-Owa-Urlpostdata': '%7B%22__type%22%3A%22SetConsumerMailboxRequest%3A%23Exchange%22%2C%22Header%22%3A%7B%22__type%22%3A%22JsonRequestHeaders%3A%23Exchange%22%2C%22RequestServerVersion%22%3A%22V2018_01_08%22%2C%22TimeZoneContext%22%3A%7B%22__type%22%3A%22TimeZoneContext%3A%23Exchange%22%2C%22TimeZoneDefinition%22%3A%7B%22__type%22%3A%22TimeZoneDefinitionType%3A%23Exchange%22%2C%22Id%22%3A%22Mountain%20Standard%20Time%22%7D%7D%7D%2C%22Options%22%3A%7B%22PopEnabled%22%3Atrue%2C%22PopMessageDeleteEnabled%22%3Afalse%7D%7D',
                                                        'X-Req-Source': 'Mail',
                                                        'Origin': 'https://outlook.live.com',
                                                        'Sec-Fetch-Dest': 'empty',
                                                        'Sec-Fetch-Mode': 'cors',
                                                        'Sec-Fetch-Site': 'same-origin',
                                                    }

                                                    params = {
                                                        'action': 'SetConsumerMailbox',
                                                        'app': 'Mail',
                                                        'n': '77',
                                                    }

                                                    response = s.post('https://outlook.live.com/owa/0/service.svc', params=params, headers=headers,timeout=15, proxies=proxy)
                                                    if(response.json()['WasSuccessful']):
                                                        print("DONE Account created with ipop!")
                                                except Exception as x:
                                                    #print(repr(x))
                                                    print('DONE  Account created no ipop but others!'.upper())
                                                    break
                                            except:
                                                print('xz WARNING MAIL')
                                                if ddds>=4:
                                                    raise Exception('xz WARNING MAIL')
                                        MAIL=f"{MAIL}@{do}.com"
                                        #ersin=0
                                        cretm=True
                                        if False:
                                            x=0
                                            while x<20:
                                                try:
                                                    
                                                    mm=mmail.mail_by_login(MAIL,MPASS,'hot')
                                                    break
                                                except:
                                                    time.sleep(1)
                                                x+=1
                                                    
                                            if x>=20:
                                                raise Exception('broken some')
                                            cretm=False
                                        tor=[MAIL,MPASS]
                                        tor_g.append(tor)
                                        
                                        #print(proxy_id)#
                                        
                                    except Exception as x:
                                        raise Exception(f"MAIL ERROR {repr(x)}")
                                    
                                return MAIL,MPASS
                            except Exception as zxcc:
                                
                                raise Exception(zxcc)
                            finally:
                                try:
                                    s.close()
                                except:
                                    pass
                    if tor!=[]:
                        cretm=False
                        MAIL=tor[0]
                        MPASS=tor[1] 

                        if '@gmx' in MAIL:
                            typegh='gmx'
                        elif '@gmail' in MAIL:
                            typegh='gmail'
                        elif '@outlook' in MAIL or '@hotmail' in MAIL:
                            typegh='hot'
                        elif '@mail' in MAIL:
                            typegh='mail'
                        elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                            typegh='rambler'
                        try:
                            mm=mmail.mail_by_login(MAIL,MPASS,typegh)
                        except:
                            try:
                                tor_g.remove(tor)
                            except:
                                pass
                            tor=[]



                    
                    d1,d2,d3=None,None,None
                    
                    if tor!=[]:
                        try:
                            s,flow,mail,name,head,d1,d2,d3,ua,somer=check_tor([MAIL,MPASS])

                        except Exception as zxc:
                            if 'e400' in str(zxc):
                                try:
                                    tor_g.remove(tor)
                                except:
                                    pass
                                if 'begin e400' not in str(zxc):
                                    
                                    tor_g.append(tor)
                                else:
                                    with lock:
                                        with open(f'/root/work/create_and_unban_SYSTEM/{systemn}/hotc_clear.txt','a') as mim:
                                            mim.writelines(f"{MAIL}:{MPASS}\n")
                                            writ=True
                            tor=[]
                            #s.close()
                            raise Exception(zxc)

                    if True:        
                        if tor==[]:
                            doda2=True
                            repmail=False
                            if do_mail: #backwards
                                print(1)
                                towakas=''
                                while True:
                                    try:
                                        with lock:
                                            with open(f'create_and_unban_SYSTEM/mails.txt','r') as acpma:
                                                acpma=acpma.readlines()
                                            if len(acpma)<1:
                                                break
                                            towakas=acpma[0]
                                            with open(f'create_and_unban_SYSTEM/mails.txt','w') as acpmaw:
                                                acpmaw.writelines(acpma[1:])

                                        MAIL=towakas.split(':')[0]
                                        MPASS=towakas.split(':')[1].replace('\n','')
                                        if '@gmx' in MAIL:
                                            typegh='gmx'
                                        elif '@gmail' in MAIL:
                                            typegh='gmail'
                                        elif '@outlook' in MAIL or '@hotmail' in MAIL:
                                            typegh='hot'
                                        elif '@mail' in MAIL:
                                            typegh='mail'
                                        elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                                            typegh='rambler'

                                        try:
                                            mm=mmail.mail_by_login(MAIL,MPASS,typegh)
                                            tor=[MAIL,MPASS]
                                            print(MAIL)
                                            
                                            doda2=False
                                            repmail=True
                                            break
                                        except:
                                            with lock:
                                                with open(f'create_and_unban_SYSTEM/mails.txt','r') as acpma:
                                                    acpma=acpma.readlines()
                                                with open(f'create_and_unban_SYSTEM/mails.txt','w') as acpmaw:
                                                    ttttttsw=acpma
                                                    ttttttsw.append(towakas)
                                                    acpmaw.writelines(ttttttsw)
                                            doda2=True   

                                    except Exception as zxc:
                                        print(zxc,'ERROR WARNING MAIL TO GET ERROR WARNING')     
                                        

                            if doda2:
                                print('starting OUTLOOK')
                                try:
                                    MAIL,MPASS=create_outlook()
                                except Exception as zxc:
                                    
                                    raise Exception(zxc)
                                tor=[MAIL,MPASS]
                            

                        else:
                            print('TOR',MAIL)
                        
                        


                        
                    if True:
                        password=''.join(random.choices(string.ascii_uppercase + string.digits, k=8))+str(randint(1,19))

                        if d1==None:
                            try:
                                s,flow,mail,name,head,d1,d2,d3,ua,somer=check_tor([MAIL,MPASS])
                            except Exception as zxc:
                                if 'e400' in str(zxc):
                                    
                                    try:
                                        tor_g.remove(tor)
                                    except:
                                        pass
                                    if 'begin e400' not in str(zxc):
                                        tor_g.append(tor)
                                    else:
                                        with lock:
                                            with open(f'/root/work/create_and_unban_SYSTEM/{systemn}/hotc_clear.txt','a') as mim:
                                                mim.writelines(f"{MAIL}:{MPASS}\n")
                                                writ=True
                                    tor=[]
                                
                                if False:
                                    print(repr(zxc))
                                    print('starting OUTLOOK')
                                
                                    MAIL,MPASS=create_outlook()
                                    raise Exception("DONE POSLE OUTLOOK, POHUI MI RABOTAEM NA POTOKI")

                                else:
                                    #er-=1
                                    pass
                                
                                raise Exception(zxc)

                        #time.sleep(random.randint(6,15))
                        pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"EnterPassword","enter_password":{"password":password,"link":"next_link"}}]}
                        r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                        #r.close() 
                        for i in r.headers:
                            if 'csrf' in i:
                                #print(r.headers[i])
                                s.headers['x-csrf-token']=r.headers[i]

                        try:
                            #print(r.text,r)
                            # with open(f'mailshot{totmn}.txt','w') as acpmtw:
                            #     acpmtw.writelines(acpmm[1:])
                            lol=r.json()['subtasks'][0]['open_account']['user']['screen_name']
                            uidm=r.json()['subtasks'][0]['open_account']['user']['id_str']
                            #print(r)
                            flow=r.json()['flow_token']
                            #print('VALID',head)
                        except Exception as x: 
                            print('INVALID',head,s.cookies.get_dict())
                            
                            try:
                                print(r.text,'password 1')
                            except:
                                with open(f"systemAAA{systemn}.txt",'w') as aaa:
                                    aaa.write(r.text)
                                print(r,'password 1')
                        
                        
                            if 't complete your signup right now' not in r.text:

                                try:
                                    tor_g.remove(tor)
                                    tor_g.append(tor)
                                except:
                                    pass
                                tor=[]    
                                #tor_g[number_t]=tor

                                # with lock:
                                #     with open(f'/root/work/create_and_unban_SYSTEM/{systemn}/hotc.txt','a') as mim:
                                #         mim.write(f"{MAIL}:{MPASS}\n")
                                
                            else:
                                #time.sleep(random.randint(6,15))
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"EnterPassword","enter_password":{"password":password,"link":"next_link"}}]}
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)

                                #r.close() 
                                for i in r.headers:
                                    if 'csrf' in i:
                                        #print(r.headers[i])
                                        s.headers['x-csrf-token']=r.headers[i]
                                lol=None
                                try:
                                    #print(r.text,r)
                                    # with open(f'mailshot{totmn}.txt','w') as acpmtw:
                                    #     acpmtw.writelines(acpmm[1:])
                                    lol=r.json()['subtasks'][0]['open_account']['user']['screen_name']
                                    uidm=r.json()['subtasks'][0]['open_account']['user']['id_str']
                                    flow=r.json()['flow_token']
                                    #print(r)
                                except Exception as x: 
                                    try:
                                        print(r.text,'password 2')
                                    except:
                                        with open(f"systemAAA{systemn}.txt",'a') as aaa:
                                            aaa.write(f"\n{r.text}")
                                        print(r,'password 2')

                                if 't complete your signup right now' not in r.text or lol==None:   
                                    try:
                                        tor_g.remove(tor)
                                        tor_g.append(tor)
                                    except:
                                        pass
                                    raise Exception('e400 password')
                        ##r.close()    
                        
                                
                        try:
                                    tor_g.remove(tor)
                        except:
                            pass
                        for i in r.headers:
                            if 'csrf' in i:
                                #print(r.headers[i])
                                s.headers['x-csrf-token']=r.headers[i]




                        ##time.sleep(random.randint(4,8))

                        #4ea0a4ecc77782060c31822c6a04a28d2f4b0a7a7aa4677c506681b8a147a64c3bd1e7d500d41f89fc399bb939adfa49487803eaecab8caf8a13c25414ebf7d48dee36380e875e980c306c594a00e84e

                        #time.sleep(random.randint(6,15))
                        r=s.get(r'https://api.twitter.com/graphql/E1y4CwfVcatdt8uaixkB0g/Viewer?variables=%7B%22withCommunitiesMemberships%22%3Atrue%2C%22withCommunitiesCreation%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Atrue%7D&features=%7B%22responsive_web_twitter_blue_verified_badge_is_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D',proxies=proxy,headers={'User-Agent':head['user-agent']})
                        #print('GET NEW CSRF')
                        #r.close() 
                        head['x-csrf-token']=s.cookies.get_dict()['ct0']

                        repmail=False

                        

                        #time.sleep(random.randint(6,15))
                        print('sdelal')
                        if True:
                            #time.sleep(random.randint(4,8))
                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"skip_link"}}]}
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)

                            #print(r)

                            try:
                                flow=r.json()['flow_token']
                            except:
                                try:
                                    print(r.text,'skip_ava')
                                except:
                                    pass

                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_ava')





                            #time.sleep(random.randint(4,8))

                            #time.sleep(random.randint(6,15))
                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"UsernameEntryBio","enter_username":{"link":"skip_link"}}]}
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)

                            #print(r)
                            try:
                                flow=r.json()['flow_token']
                            except:
                                print(r.text,'skip_username')
                                print("TRY NEW REQ")
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"next_link"}},{"subtask_id":"SelectBanner","select_banner":{"link":"skip_link"}},{"subtask_id":"EnterProfileBio","enter_text":{"text":'',"link":"next_link"}},{"subtask_id":"EnterProfileLocation","enter_text":{"text":'',"link":"next_link"}},{"subtask_id":"CallToAction","cta":{"link":"next_link"}}]}
                                #pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"next_link"}},{"subtask_id":"SelectBanner","select_banner":{"link":"skip_link"}},{"subtask_id":"EnterProfileBio","enter_text":{"text":'ebaaat',"link":"next_link"}},{"subtask_id":"EnterProfileLocation","enter_text":{"text":'hui',"link":"next_link"}},{"subtask_id":"CallToAction","cta":{"link":"next_link"}}]}
                                #time.sleep(random.randint(6,15))
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',json=pay,headers=head,timeout=15,proxies=proxy)
                                try:
                                    flow=r.json()['flow_token']
                                except:
                                    print(r.text,'"TRY NEW REQ"')
                                #time.sleep(random.randint(6,15))
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"UsernameEntryBio","enter_username":{"link":"skip_link"}}]}
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                                try:
                                    flow=r.json()['flow_token']
                                except:
                                    print(r.text,'skip_username')
                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_username')



                            #time.sleep(random.randint(4,8))


                            #time.sleep(random.randint(6,15))
                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"NotificationsPermissionPrompt","notifications_permission_prompt":{"link":"skip_link"}}]}
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)

                            #print(r)

                            try:
                                flow=r.json()['flow_token']
                            except:
                                
                                try:
                                    print(r.text,'skip_notif')
                                except:
                                    pass
                                print('ANTOHER TRY NEW')
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"UsernameEntry","enter_username":{"link":"skip_link"}}]}
                                #time.sleep(random.randint(6,15))
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)

                                #print(r)
                                try:
                                    flow=r.json()['flow_token']
                                except:
                                    pass
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"NotificationsPermissionPrompt","notifications_permission_prompt":{"link":"skip_link"}}]}
                                #time.sleep(random.randint(6,15))
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                                try:
                                    flow=r.json()['flow_token']
                                except:
                                    try:
                                        print(r.text,'skip_notif')
                                    except:
                                        pass
                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_notif')



                            #time.sleep(random.randint(4,8))




                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"InterestPickerURT","generic_urt":{"link":"next_link"}}]}
                            #time.sleep(random.randint(6,15))
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                            #print(r)
                            try:
                                flow=r.json()['flow_token']
                            except:
                                print(r.text,'skip_some1')
                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_some1')



                            #time.sleep(random.randint(4,8))



                            pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"UserRecommendationsURTFollowGating","user_recommendations_urt":{"link":"next_link","selected_user_recommendations":["44196397"]}}]} #str(prev) #random.choice(['1397576363205439489','2740288019','1381699264011771906'])
                            #time.sleep(random.randint(6,15))
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                            #print(r)
                            try:
                                flow=r.json()['flow_token']
                            except Exception as x:
                                print(r.text,'skip_some2')

                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_some2')



                            #time.sleep(random.randint(4,8))


                            pay={"flow_token":flow,"subtask_inputs":[]}
                            #time.sleep(random.randint(6,15))
                            r=s.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                            #print(r)


                            for i in r.headers:
                                if 'csrf' in i:
                                    print(r.headers[i])
                                    s.headers['x-csrf-token']=r.headers[i]

                            #print('skip_some3')



                        # r=s.post('https://api2.branch.io/v1/profile',headers=head,timeout=15,proxies=proxy)
                        # print(r)

                        #input(f'ebat done? {lol} {password} {mail}')

                        #time.sleep(random.randint(4,8))

                        #ZAPOLNENOST
                        if True:
                            try:
                                head['authorization']='Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
                                
                                pay={"input_flow_data":{"flow_context":{"debug_overrides":{},"start_location":{"location":"manual_link"}}},"subtask_versions":{"action_list":2,"alert_dialog":1,"app_download_cta":1,"check_logged_in_account":1,"choice_selection":3,"contacts_live_sync_permission_prompt":0,"cta":7,"email_verification":2,"end_flow":1,"enter_date":1,"enter_email":2,"enter_password":5,"enter_phone":2,"enter_recaptcha":1,"enter_text":5,"enter_username":2,"generic_urt":3,"in_app_notification":1,"interest_picker":3,"js_instrumentation":1,"menu_dialog":1,"notifications_permission_prompt":2,"open_account":2,"open_home_timeline":1,"open_link":1,"phone_verification":4,"privacy_options":1,"security_key":3,"select_avatar":4,"select_banner":2,"settings_list":7,"show_code":1,"sign_up":2,"sign_up_review":4,"tweet_selection_urt":1,"update_users":1,"upload_media":1,"user_recommendations_list":4,"user_recommendations_urt":1,"wait_spinner":3,"web_modal":1}}
                                #time.sleep(random.randint(6,15))
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json?flow_name=setup_profile',headers=head,timeout=15,json=pay,proxies=proxy)
                                #r.close() 
                                #print(r)
                                #print('start_up')

                                if False:
                                    pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"skip_link"}}]}
                                    r=requests.post('https://api.twitter.com/1.1/onboarding/task.json',headers=head,timeout=15,json=pay,proxies=proxy)
                                    print(r.text,r,)
                                    pass



                                if True:
                                    media_id=None
                                    wers=0
                                    while True:
                                        if default==False:
                                            hcp=random.randint(1,100)
                                            if hcp>50:
                                                sp=f'av/{random.choice(os.listdir(r"av"))}'
                                                
                                            else:
                                                sp=f'pics/{random.choice(os.listdir(r"pics"))}'

                                        else:
                                            if random.randint(1,100)>50:
                                                response = requests.get('https://random.imagecdn.app/500/500', stream=True)
                                                with open(r'1.jpg', 'wb') as out_file:
                                                    for chunk in response:
                                                        out_file.write(chunk)
                                                sp='1.jpg'
                                            else:
                                                sp=f'av/{random.choice(os.listdir(r"av"))}'

                                        mgm=open(sp, 'rb')
                                        files = {"media" : mgm}
                                        
                                        #print(1)
                                        try:
                                            
                                            #media_idd = twitter.post(f'https://upload.twitter.com/1.1/media/upload.json?additional_owners={uidm}', files = files, proxies=proxy)
                                            #media_id=media_idd.json()['media_id_string']
                                            #time.sleep(random.randint(6,15))
                                            r=s.post('https://upload.twitter.com/1.1/media/upload.json?media_category=tweet_image',files = files,headers=head,timeout=15)#,proxies=proxy)
                                            #r.close() 
                                            media_id=r.json()['media_id_string']
                                            mgm.close() 

                                            break
                                        except:
                                            
                                            wers+=1
                                            try:
                                                #print(media_idd.text)
                                                print(r.text)
                                            except:
                                                pass
                                            if wers>4:
                                                mgm.close() 
                                                raise Exception('CHOTO S MEDIA XZ')
                                                
                                        time.sleep(3)
                                else:
                                    
                                        bts=os.path.getsize(sp)
                                        r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=INIT&total_bytes={bts}&media_type=image%2Fjpeg',proxies=proxy,headers=head,timeout=15,files = files)
                                        print(r.text,r)
                                        print(1)
                                        media_id=r.json()['media_id']
                                        r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=APPEND&media_id={media_id}&segment_index=0',files = files,headers=head,timeout=15,proxies=proxy)
                                        print(r.text,r)
                                        print(2)
                                        mimi=md5(sp)
                                        print(mimi)
                                        r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=FINALIZE&media_id={media_id}&original_md5={mimi}',files = files,headers=head,timeout=15,proxies=proxy)
                                        print(r.text,r)
                                        print(3)
                                        media_id=input('media_id=')
                                    
                                #time.sleep(random.randint(6,15))        
                                r=s.post(f'https://api.twitter.com/1.1/account/update_profile_image.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&include_ext_has_nft_avatar=1&include_ext_is_blue_verified=1&include_ext_verified_type=1&skip_status=1&return_user=true&media_id={media_id}',headers=head,timeout=15,proxies=proxy)


                                

                                
                                #print(2)
                                if True:
                                    media_id=None
                                    wers=0
                                    while True:
                                        if default==False:
                                            sp=f'banners/{random.choice(os.listdir(r"banners"))}'

                                        else:
                                            if random.randint(1,100)>50:
                                                response = requests.get('https://random.imagecdn.app/600/250', stream=True)
                                                with open(r'2.jpg', 'wb') as out_file:
                                                    for chunk in response:
                                                        out_file.write(chunk)
                                                sp='2.jpg'

                                                image_path=sp
                                                fixed_width = 1080
                                                img = Image.open(image_path)
                                                # получаем процентное соотношение
                                                # старой и новой ширины
                                                width_percent = (fixed_width / float(img.size[0]))
                                                # на основе предыдущего значения
                                                # вычисляем новую высоту
                                                height_size = int((float(img.size[1]) * float(width_percent)))
                                                
                                                # меняем размер на полученные значения
                                                new_image = img.resize((fixed_width, height_size))

                                                razd='/'
                                                
                                                image_path2=image_path.split(razd)[-1]


                                                #new_image.save(f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}")



                                                #img = Image.open(f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}")
                                                img=new_image
                                                size = img.size
                                                width, height = img.size
                                                # обрезаем картинку
                                                new_image = img.crop((0,0,1080,360))
                                                new_image = img.crop((0,0,1080,360))
                                                #sp=f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}"
                                                sp='2.jpg'
                                                new_image.save(sp)
                                                
                                            else:
                                                sp=f'banners/{random.choice(os.listdir(r"banners"))}'
                                        if False:
                                            image_path=sp
                                            fixed_width = 1080
                                            img = Image.open(image_path)
                                            # получаем процентное соотношение
                                            # старой и новой ширины
                                            width_percent = (fixed_width / float(img.size[0]))
                                            # на основе предыдущего значения
                                            # вычисляем новую высоту
                                            height_size = int((float(img.size[1]) * float(width_percent)))
                                            
                                            # меняем размер на полученные значения
                                            new_image = img.resize((fixed_width, height_size))

                                            razd='/'
                                            
                                            image_path2=image_path.split(razd)[-1]


                                            #new_image.save(f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}")



                                            #img = Image.open(f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}")
                                            img=new_image
                                            size = img.size
                                            width, height = img.size
                                            # обрезаем картинку
                                            new_image = img.crop((0,0,1080,360))
                                            new_image = img.crop((0,0,1080,360))
                                            sp=f"{razd.join(image_path.split(razd)[:-1])}{razd}cropped{razd}{image_path2}"
                                            new_image.save(sp)
                                        
                                        mgm=open(sp, 'rb')
                                        files = {"media" : mgm}
                                        try:
                                            
                                            #media_idd = twitter.post(f'https://upload.twitter.com/1.1/media/upload.json?additional_owners={uidm}', files = files, proxies=proxy)
                                            #media_id=media_idd.json()['media_id_string']
                                            #time.sleep(random.randint(6,15))
                                            r=s.post('https://upload.twitter.com/1.1/media/upload.json?media_category=tweet_image',files = files,headers=head,timeout=15)#,proxies=proxy)
                                            #r.close() 
                                            media_idb=r.json()['media_id_string']
                                            mgm.close()
                                            break
                                        except:
                                            
                                            wers+=1
                                            try:
                                                #print(media_idd.text)
                                                print(r.text)
                                            except:
                                                pass
                                            if wers>4:
                                                mgm.close()
                                                raise Exception('CHOTO S MEDIA XZ 2')
                                                
                                        time.sleep(3)
                                else:
                                    bts=os.path.getsize(sp)
                                    r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=INIT&total_bytes={bts}&media_type=image%2Fjpeg&media_category=banner_image',proxies=proxy,headers=head,timeout=15)
                                    print(r.text,r)
                                    print(12)
                                    media_id=r.json()['media_id']
                                    r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=APPEND&media_id={media_id}&segment_index=0',files = files,headers=head,timeout=15,proxies=proxy)
                                    print(r.text,r)
                                    print(22)
                                    mimi=md5(sp)
                                    print(mimi)
                                    r=s.post(f'https://upload.twitter.com/i/media/upload.json?command=FINALIZE&media_id={media_id}&original_md5={mimi}',headers=head,timeout=15,proxies=proxy)
                                    print(r.text,r)
                                    print(32)



                                #time.sleep(random.randint(4,8))


                                #time.sleep(random.randint(6,15))
                                r=s.post(f'https://api.twitter.com/1.1/account/update_profile_banner.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&include_ext_has_nft_avatar=1&include_ext_is_blue_verified=1&include_ext_verified_type=1&skip_status=1&return_user=true&media_id={media_idb}',headers=head,timeout=15,proxies=proxy)
                                #r.close() 
                                #print(r)
                                #print('upload banner')
                                defik=False



                            

                            except Exception as x:
                                defik=True
                                print(repr(x))

                            r=name
                            smlsd=[r'%E2%9A%9C', r'%EF%B8%8F', r'%F0%9F%91%81', r'%E2%80%8D', r'%F0%9F%97%A8', r'%E2%99%A6', r'%EF%B8%8F', r'%E2%9D%A4', r'%EF%B8%8F', r'%E2%98%A2', r'%EF%B8%8F', r'%F0%9F%92%8A', r'%F0%9F%94%A7', r'%F0%9F%93%B8', r'%E2%9C%B4', r'%EF%B8%8F', r'%F0%9F%92%AF', r'%E2%9A%A0', r'%EF%B8%8F', r'%F0%9F%92%9C', r'%F0%9F%92%9A', r'%F0%9F%92%99', r'%F0%9F%92%9B', r'%F0%9F%A7%A1', r'%F0%9F%96%A4', r'%F0%9F%A4%8D', r'%F0%9F%A9%B8', r'%F0%9F%94%AE', r'%F0%9F%92%B5', r'%F0%9F%92%B8', r'%E2%9B%A9', r'%EF%B8%8F', r'%E2%9A%93', r'%EF%B8%8F', r'%F0%9F%A4%A0', r'%F0%9F%98%8E', r'%F0%9F%91%BD', r'%F0%9F%91%BA', r'%F0%9F%99%8F', r'%F0%9F%91%81', r'%EF%B8%8F', r'%F0%9F%A7%A0', r'%F0%9F%91%80', r'%F0%9F%91%85', r'%F0%9F%A6%BE', r'%F0%9F%92%AA', r'%F0%9F%97%A3', r'%EF%B8%8F', r'%F0%9F%92%8B', r'%E2%98%82', r'%EF%B8%8F', r'%F0%9F%90%B2', r'%F0%9F%8C%9A', r'%F0%9F%8C%9D', r'%F0%9F%8C%9B', r'%F0%9F%8C%9C', r'%F0%9F%8C%88', r'%E2%98%94', r'%EF%B8%8F', r'%E2%9D%84', r'%EF%B8%8F', r'%F0%9F%92%A5', r'%E2%9C%A8', r'%F0%9F%94%A5', r'%E2%9A%A1', r'%EF%B8%8F', r'%F0%9F%8C%8A', r'%F0%9F%92%A6', r'%F0%9F%8C%AA', r'%EF%B8%8F', r'%F0%9F%8D%99', r'%F0%9F%8D%BE', r'%F0%9F%8D%BA', r'%F0%9F%8D%BB', r'%F0%9F%8D%B7', r'%F0%9F%8E%AF', r'%F0%9F%A7%A9', r'%F0%9F%97%91', r'%EF%B8%8F', r'%F0%9F%92%8E', r'%F0%9F%92%B0', r'%E2%9A%99', r'%EF%B8%8F', r'%F0%9F%A7%AC', r'%F0%9F%97%9D', r'%EF%B8%8F', r'%F0%9F%92%9F', r'%E2%98%A2', r'%EF%B8%8F', r'%E2%98%AF', r'%EF%B8%8F', r'%F0%9F%94%AF', r'%E2%98%AA', r'%EF%B8%8F', r'%E2%9C%94', r'%EF%B8%8F', r'%F0%9F%94%9D', r'%F0%9F%92%B2', r'%F0%9F%94%94', r'%F0%9F%8E%B4', r'%F0%9F%9A%A9', r'%F0%9F%8F%B4', r'%E2%80%8D', r'%E2%98%A0', r'%EF%B8%8F', r'%F0%9F%8F%B3', r'%EF%B8%8F', r'%E2%80%8D', r'%F0%9F%8C%88', r'%F0%9F%8F%B4', r'%F0%9F%8F%B3', r'%EF%B8%8F']
                            
                            try:
                                smile=random.choice(smlsd)
                                smile2=random.choice(smlsd)
                                smlr=random.choice(smlsd)
                                
                                chsmil=randint(1,3)
                                if chsmil<1:
                                    chsmil=1
                                if randint(1,100)>80:
                                    smlr=random.choice(['$','!','*','/','><',':)',':3',' L ',' W ','|'])
                                    smlr=urllib.parse.quote(smlr)
                                sg=randint(1,100)
                                if somer:
                                    while sg<=30:
                                        sg=randint(1,100)
                                if sg>80:
                                    r=f'{r}{smlr*chsmil}'
                                elif sg>60:
                                    r=f'{smlr*chsmil}{r}'
                                elif sg>40:
                                    r=f'{smlr*chsmil}{r}{smlr*chsmil}'     
                            except Exception as x:
                                print(repr(x))
                                smile=''
                                smile2=''
                                smlr=''


                            while True:
                                sudba=randint(1,1000)
                                

                                if sudba >=500:
                                    if False:
                                        try:
                                            bib=False
                                            response = openai.Completion.create(model="text-davinci-003", prompt="write super unique and creative twiiter bio with crypto, nft, tokens and just some random theme. you can use emojis and sashtags.",temperature=0.9, max_tokens=160)
                                            text=response['choices'][0]['text'].replace('\n\n','')
                                            text = text.encode("utf-8")
                                            text = text.decode("utf-8")
                                            tex=urllib.parse.quote(text)
                                        except Exception as xxz:
                                            #print(repr(xxz))
                                            bib=True
                                            sudba=randint(1,499)
                                    else:
                                        bib=False
                                        tex=''
                                        while tex.replace(' ','')=='' or len(tex)>=160:
                                            try:
                                                with open('bios_gpt.txt','r') as acpb:
                                                    acpb = acpb.readlines()
                                                    
                                                tex=acpb[randint(0,len(acpb))].encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                                                tex=tex.replace('\n','')
                                                tex=tex.replace(r'#\n','\n')
                                                tex=urllib.parse.quote(tex)
                                            except:
                                                with open('bios_gpt.txt','rb') as acpb:
                                                    acpb = acpb.readlines()
                                                    
                                                tex=acpb[randint(0,len(acpb))].decode().encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                                                tex=tex.replace('\n','')
                                                tex=tex.replace(r'#\n','\n')
                                                tex=urllib.parse.quote(tex)

                                            

                                if sudba<500:
                                    sslk=False
                                    ssr=False
                                    ssa=False
                                    #if sudba>400:
                                    if False:
                                        bib=True
                                        try:
                                            with open('bios.txt','rb') as acpb:
                                                acpb = acpb.readlines()
                                                
                                                tex=acpb[randint(0,len(acpb))].decode()

                                                tex=tex.replace('\n','')
                                                tex=urllib.parse.quote(tex)
                                        except:
                                            with open('bios.txt','r') as acpb:
                                                acpb = acpb.readlines()
                    
                                                tex=acpb[randint(0,len(acpb))]
                                                tex=tex.replace('\n','')
                                                tex=urllib.parse.quote(tex)

                                    else:
                                        bib=False
                                        chsm=randint(1,100)
                                        
                                        if chsm>80:
                                            sslk=True
                                        elif chsm>60:
                                            ssr=True
                                        elif chsm>40:
                                            ssa=True

                                        #des=random.choice([' %2',r' %2%2',' !!', ' !', r' %2%2','%2',' and',' also', ' %3B', ' %3A', ' %2C'])
                                        des1=random.choice([' +', ' &',' and',' also', ' ;', ' ,', ' .','/','\\'])
                                        des2=random.choice([' .',' ,',' |',' &', ' ;','',' ||',' +'])+'\n'
                                        if random.randint(1,100)>60:
                                            des=des2
                                        else:
                                            des=des1

                                        des=urllib.parse.quote(des)
                                        if des=='and' or des=='also':
                                            chs=randint(1,100)
                                            if chs>66:
                                                des=des.capitalize()
                                            elif chs>33:
                                                des=f'{des[0].capitalize()}{des[1:]}'
                                        if default:
                                            tit1=[' Sidehustle',' Art',' Games',' Fashion',' Gym',' Books',' Market',' Cakes',' Food',' Hats',' Bodybuilding',' Football',' Joy',' Milf',' Marketplace','Ski','C#','Java']

                                        else:
                                            tit1=[' Sidehustle',' NFT',' JPEG',' Crypto',' Art',' Games',' Fashion',' Gym',' Books',' Market',' Cakes',' Food',' Hats',' Bodybuilding',' Football',' Joy',' Milf',' Marketplace','Ski','C#','Java']

                                        tex1=random.choice(tit1)+random.choice([' Lover',' Ethusiast',' Collector',' Hunter','', ' dumbass',' Marketer ', ' Beast',' Fan ',' Guy '])
                                        
                                        if default==False:
                                            tex2=random.choice([random.choice([' Only',' Go',''])+random.choice([' Degen',' Smart'])+random.choice([' Moves','']),random.choice([' Be smart',' Be happy',f' Enjoy {random.choice(["your ",""])}life',' Be healthy']),random.choice(['he/him','she/her','they/them']),f' {randint(18,27)} {random.choice(["yo","y.o.","years","years old",""])}'])
                                        else:
                                            tex2=tex2=random.choice([random.choice([f' Be {random.choice(["smart","happy","healthy","rich","free","yourself","you","respectful"])}',f' Enjoy {random.choice(["your ",""])}life',' BLM',' LGBTQ+'])])

                                        tex3=random.choice([' Artist',' Sidehustler',' Sport',' Art works',' 3d Artist',' 3d Art works',' Advisor',' Promoter',' Designer',' Developer',' Coder',' newb', ' Creator',' Gamer',' Player',' Boxer',' Soccer player',' Chef',' Pro'])
                                        
                                        tex4=random.choice([f'{random.choice([" I am",""])} lazy{random.choice([" af",""])}',' Anime',' Manga',' Style',' Building',' Enjoing Life',' web3',' Games',' Health',' The best',f'{randint(1,3)*"0"}{randint(1,9)}'])

                                        tex5=random.choice([' Working',' Trying',' Hitting',' Building',' Playing',' Farming',' Grinding', ' Researching',' In mood',' Suffering',' Fighting inner demons',' high'])+random.choice([' hard','',' rn',' af'])
                                        if default==False:
                                            tex6=random.choice([' DM', ' dm', ' text',' contact'])+random.choice([' me', ''])+random.choice([' for',''])+random.choice([' Promo', ' Collab',' Work',' advice',' help'])
                                        else:
                                            tex6=random.choice([' DM', ' dm', ' text',' contact'])+random.choice([' me', ''])+random.choice([' for',''])+random.choice([' anything',' any reason', ' work',' advice',' help',' converstion']+random.choice([f'{random.choice([" at",""])} any time','']))
                                        
                                        texf=random.choice([' etc', randint(1,3)*' more'+random.choice([" interesting",' cool',' different',""])+random.choice([" shit"," stuff", ' things',]),' other',' anything'])

                                        texx=[tex1,tex2,tex3,tex4,tex5,tex6]
                                        if randint(0,100)>40:
                                            rorx=randint(2,4)
                                        else:
                                            rorx=randint(1,5)
                                        
                                        texx=texx[:rorx]
                                        texxt=[]
                                        for ti in texx:
                                            if randint(1,100)>5:
                                                sm=smile
                                            else:
                                                sm=urllib.parse.quote(random.choice([' ',' :3 ',' <3 ',' ! ', ' ? ',' :) ',' ;) ']))

                                            ti=urllib.parse.quote(ti)
                                            if sslk:
                                                ti=f'{ti}{sm}'
                                            elif ssr:
                                                ti=f'{sm}{ti}'
                                            elif ssa:
                                                ti=f'{smile}{ti}{smile}'
                                            texxt.append(ti)
                                        random.shuffle(texxt)

                                        tex=des.join(texxt)
                                        if randint(1,100)>90:
                                            tex+=des
                                            tex+=texf



                                    tex=tex.strip()
                                    trt=[False,False,False]
                                    if ssa==False and ssr==False and sslk==False and bib==True:
                                        amsh=randint(1,2)
                                        
                                        for i in range(amsh):
                                            trt[i]=True
                                        random.shuffle(trt)

                                    if default==False:
                                        asdf=50
                                    else:
                                        asdf=75
                                    if randint(1,100)>asdf:
                                        trt[0]=True

                                    if trt[0]==True:
                                        tex=f"{smile2} {tex} {smile2}"

                                    if default==False:
                                        sash=['okaybears','sport','health','NFTcommunity','solana','eth','bnb','avax','btc','web3','metaverse','bayc','mayc','apes','nft','arts','3d','anime','manga','promo','advisor','dao','rawr','degen','sniper','dao','BLM','sport','health','metoo','Trump','Biden','PeaceInWorld','Nowars','StopWars','SlavesFree','blackhistorymonth','sidehustler','JAVA','Python','c++','cc','Gamedev','IT','Freedom']
                                        doll=['WIPE','DOGE','ZII',"USDT","LUNA",'MEX','RAWR','ETH',"SOLANA",'SAND','USDC','DAW','BNB','BUSD']
                                    else:
                                        sash=['BLM','sport','health','metoo','Trump','Biden','PeaceInWorld','Nowars','StopWars','SlavesFree','blackhistorymonth','sidehustler','JAVA','Python','c++','cc','Gamedev','IT','Freedom','arts','3d','anime','manga']
                                        doll=[]

                                    if randint(1,100)>40:
                                        trt[1]=True

                                    if trt[1]==True:
                                        amsh=randint(1,4)
                                        random.shuffle(sash)
                                        for i in sash[:amsh]:
                                            if randint(1,100)>50:
                                                i=i.capitalize()

                                            if randint(1,100)>30:
                                                tex=f'{tex} #{i}'    
                                            else:
                                                tex=f'#{i} {tex}' 

                                    if randint(1,100)>60:
                                        trt[2]=True

                                    if trt[2]==True:
                                        amsh=randint(1,2)           
                                        random.shuffle(doll)
                                        for i in doll[:amsh]:
                                            if randint(1,100)>50:
                                                tex=f'{tex} ${i}'
                                            else:
                                                tex=f'${i} {tex}' 

                                
                                

                                if True:
                                    tex=tex.replace('#','%23')
                                    tex=tex.replace('$','%24')
                                    tex=tex.replace(' ','%20')
                                    r=r.replace('#','%23')
                                    r=r.replace('$','%24')
                                    r=r.replace(' ','%20')
                                    tex=tex.replace('  ',' ')
                                else:
                                    tex=urllib.parse.quote(tex)

                                if len(tex)<160:
                                    break
                            #print(head)


                            #time.sleep(random.randint(4,8))


                            if True:
                                pay=f'birthdate_day={d1}&birthdate_month={d2}&birthdate_year={d3}&birthdate_visibility=self&birthdate_year_visibility=self&displayNameMaxLength=50&name={r}&description={tex}&location={urllib.parse.quote(lcc[cl])}'
                                #time.sleep(random.randint(6,15))
                                r=s.post('https://twitter.com/i/api/1.1/account/update_profile.json',params=pay,headers=head,timeout=15,proxies=proxy)
                                #r.close() 
                            else:
                                pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"next_link"}},{"subtask_id":"SelectBanner","select_banner":{"link":"skip_link"}},{"subtask_id":"EnterProfileBio","enter_text":{"text":urllib.parse.unquote(tex),"link":"next_link"}},{"subtask_id":"EnterProfileLocation","enter_text":{"text":lcc[cl],"link":"next_link"}},{"subtask_id":"CallToAction","cta":{"link":"next_link"}}]}
                                #pay={"flow_token":flow,"subtask_inputs":[{"subtask_id":"SelectAvatar","select_avatar":{"link":"next_link"}},{"subtask_id":"SelectBanner","select_banner":{"link":"skip_link"}},{"subtask_id":"EnterProfileBio","enter_text":{"text":'ebaaat',"link":"next_link"}},{"subtask_id":"EnterProfileLocation","enter_text":{"text":'hui',"link":"next_link"}},{"subtask_id":"CallToAction","cta":{"link":"next_link"}}]}
                            
                                r=s.post('https://api.twitter.com/1.1/onboarding/task.json',json=pay,headers=head,timeout=15,proxies=proxy)

                            #print(r)
                            #print('bio')

                            cl=cl%(len(lcc)-1)
                            cl+=1
                            cl_d[number_t]=cl

                            if False:
                                mm=[]
                                try:
                                    random.shuffle(uc)
                                    #print(uc[0])
                                    mm.append(uc[0])
                                    #mm.append(acp[-1].split(':')[-2])
                                    #mm.append(acp[-2].split(':')[-2])
                                    pass
                                except:
                                    pass
                                for uid in mm:
                                    try:
                                        
                                        pay=f'include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&include_ext_has_nft_avatar=1&include_ext_is_blue_verified=1&include_ext_verified_type=1&skip_status=1&user_id={uid}'
                                        #pay=f'include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&include_ext_has_nft_avatar=1&include_ext_is_blue_verified=1&skip_status=1&user_id={uid}'
                                        xfs=0
                                        while True:
                                            
                                            try:
                                                                
                                                r=s.post('https://api.twitter.com/1.1/friendships/create.json',params=pay,headers=head,timeout=15,proxies=proxy)
                                                #r=requests.post('https://twitter.com/i/api/1.1/friendships/create.json',params=pay,headers=head,proxies=proxy)
                                                print(r.text,r)
                                                break
                                            except Exception as x:
                                                print(repr(x))
                                                xfs+=1
                                                print('oops')
                                                if xfs>=3:
                                                    break
                                                
                                                
                                        
                                    except UnboundLocalError:
                                        pass

                            

                            def farm_f(listt,head,cock,s,lol):
                                if len(post_list)<25:
                                    ts=25
                                else:
                                    ts=10
                                st=time.time()
                                ts=(540//len(listt))-1

                                for uidf in listt:
                                    time.sleep(ts)
                                    rf=follow(head,uidf,cock)
                                    
                                    if 'Authorization: Denied by access control' in rf.text or 'suspended, deactivated or offboarded' in rf.text or 'temporarily locked' in rf.text or rf.status_code==403:
                                        print(f'ZABANILI {lol} {time.time()-st}')
                                        # try:
                                        #     print(rf.text)
                                        # except:
                                        #     pass
                                        # print(rf)
                                        break
                                                
                                print(f'NAKRuTILI F {lol} {time.time()-st}')

                            def farm_post(post_list,head,cock,s,lol):
                                try:
                                    st=time.time()
                                    ts=6
                                    ts=(540//(len(post_list)+1))-1

                                    for tid in post_list:
                                        time.sleep(ts/2) 
                                        pay={"variables":{"tweet_id":tid,"dark_request":False},"queryId":"ojPdsZsimiJrUGLR1sjUtA"}
                                        try:
                                            rr=s.post('https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet',json=pay,headers=head,timeout=15,cookies=cock)
                                            #rr.close() 
                                        except Exception as x:
                                            print(repr(x))
                                            #time.sleep(1)
                                            try:
                                                rr=s.post('https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet',json=pay,headers=head,timeout=15,cookies=cock)
                                                #rr.close() 
                                            except:
                                                pass
                                        if 'Authorization: Denied by access control' in rr.text or 'suspended, deactivated or offboarded' in rr.text or 'temporarily locked' in rr.text or rr.status_code==403:
                                                print(f'ZABANILI {lol} {time.time()-st}')
                                                # try:
                                                #     print(rr.text)
                                                # except:
                                                #     pass
                                                # print(rr)
                                                break
                                        time.sleep(ts/2) 
                                        if len(post_list)<75:
                                            pay={"variables":f"{{\"tweet_id\":\"{tid}\"}}","queryId":"lI07N6Otwv1PhnEgXILM7A"}
                                            try:
                                                rl=s.post('https://mobile.twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet',json=pay,headers=head,timeout=15,cookies=cock)
                                            except:
                                                #time.sleep(1)
                                                try:
                                                    rl=s.post('https://mobile.twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet',json=pay,headers=head,timeout=15,cookies=cock)
                                                except:
                                                    pass
                                            if 'Authorization: Denied by access control' in rl.text or 'suspended, deactivated or offboarded' in rl.text or 'temporarily locked' in rl.text or rl.status_code==403:
                                                    print(f'ZABANILI {lol} {time.time()-st}')
                                                    # try:
                                                    #     print(rl.text)
                                                    # except:
                                                    #     pass
                                                    # print(rl)
                                                    break
                                            

                                    wers=0
                                    media_id=None
                                    time.sleep(ts/2) 
                                except:
                                    pass

                                finally:
                                    while True:
                                        
                                        while True:
                                            # hcp=random.randint(1,100)
                                            # if hcp>70:
                                            #     sp=f'av/{random.choice(os.listdir(r"av"))}'
                                            #     #gf=random.choice(os.listdir(r"D:\pictures\ins"))
                                            #     #sp=f'D:\pictures\ins\{gf}'
                                                
                                            # else:
                                                
                                            sp=f'pics/{random.choice(os.listdir(r"pics"))}'
                                                #gf=random.choice(os.listdir(r"D:\pictures\ins"))
                                                #sp=f'D:\pictures\ins\{gf}'


                                            sp1=f'pics/{random.choice(os.listdir(r"pics"))}'
                                            sp2=f'banners/{random.choice(os.listdir(r"banners"))}'
                                            sp3=f'av/{random.choice(os.listdir(r"av"))}'

                                            sp=random.choice([sp1,sp2,sp3])
                                            if '_hex' not in sp:
                                                break

                                        mgm=open(sp, 'rb')
                                        files = {"media" : mgm}
                                        
                                        
                                        try:
                                            
                                            #media_idd = twitter.post(f'https://upload.twitter.com/1.1/media/upload.json?additional_owners={uidm}', files = files, proxies=proxy)
                                            #media_id=media_idd.json()['media_id_string']
                                            r=s.post('https://upload.twitter.com/1.1/media/upload.json?media_category=tweet_image',files = files,headers=head,timeout=10,proxies=proxy)
                                            #r.close() 
                                            media_id=r.json()['media_id_string']
                                            mgm.close()
                                            break
                                        except:
                                            wers+=1
                                            if wers>4:
                                                mgm.close()
                                                print('CHOTO S MEDIA XZ FARmm')
                                                break

                                    if media_id:
                                        sud=random.randint(1,100)
                                        if sud>50:
                                            
                                            ssf=''
                                            while ssf=='':
                                                for gjj in range(3):
                                                    sud=random.randint(1,100)
                                                    if sud>70:
                                                        sashnft=['NFT','ETH','BTC','ART','NFTArt','NFTCommunity','Crypto','CryptoCommunity','NFTComunity','CryptoCommunity','Solana','SOL','Aptos','BNB']
                                                        random.shuffle(sashnft)
                                                        ssgh=randint(1,5)
                                                        if ssgh!=0:
                                                            #ssgh='#'+' #'.join(sashnft[:ssgh])
                                                            toaarara=random.choice(['#',''])
                                                            ssgh=f' {toaarara}'+f' {toaarara}'.join(sashnft[:ssgh])
                                                            
                                                            ssgh=random.choice(['\n','\n\n',' '])+ssgh
                                                        else:
                                                            ssgh=''
                                                        ssf+=ssgh
                                                    elif sud>40:
                                                        smlsd=[':eye_in_speech_bubble:',':red_heart:',':pill:',':wrench:',':camera_with_flash:',':hundred_points:',':purple_heart:',':green_heart:',':yellow_heart:',':black_heart:',':kiss_mark:',':alien:',':police_car_light:',':airplane:',':fire:',':comet:',':snowflake:',':high_voltage:',':umbrella_with_rain_drops:',':party_popper:',':wrapped_gift:',':trophy:',':crown:',':drop_of_blood:',':shinto_shrine:',':beer_mug:',':cut_of_meat:',':four_leaf_clover:',':spider_web:',':hamster:',':folded_hands:']
                                                        random.shuffle(smlsd)
                                                        asdd=random.randint(-3,3)
                                                        if asdd<1:
                                                            asdd=1
                                                        trt=smlsd[:asdd]
                                                        trtd=[]
                                                        for pspsp in trt:
                                                            trtd.append(emoji.emojize(pspsp))


                                                        ssf2=random.choice(['',' ','']).join(trtd)

                                                        if asdd==1:
                                                            asdd=random.randint(-1,3)
                                                            if asdd<1:
                                                                asdd=1
                                                            ssf2=f" {ssf2}{random.choice(['',' ',''])}"*asdd
                                                        ssf+=ssf2
                                        else:
                                            tex=''
                                            while tex.replace(' ','')=='' or len(tex)>=250:
                                                try:
                                                    with open('bios_gpt.txt','r') as acpb:
                                                        acpb = acpb.readlines()
                                                        
                                                    tex=acpb[randint(0,len(acpb))].encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                                                    tex=tex.replace('\n','')
                                                    tex=tex.replace(r'#\n','\n')
                                                    
                                                except:
                                                    with open('bios_gpt.txt','rb') as acpb:
                                                        acpb = acpb.readlines()
                                                        
                                                    tex=acpb[randint(0,len(acpb))].decode().encode("latin_1").decode("raw_unicode_escape").encode('utf-16', 'surrogatepass').decode('utf-16')
                                                    tex=tex.replace('\n','')
                                                    tex=tex.replace(r'#\n','\n')
                                                    tex=tex.replace(r'#',random.choice(['','#']))
                                                    
                                            ssf=tex

                                        try:
                                            ssf=ssf.strip()
                                        except:
                                            pass

                                        aa='yL4KIHnJPXt-JUpRDrBDDw' 
                                        pay={"variables":{"tweet_text":ssf,"dark_request":False,"media":{"media_entities":[{"media_id":media_id,"tagged_users":[]}],"possibly_sensitive":False},"withDownvotePerspective":False,"withReactionsMetadata":False,"withReactionsPerspective":False,"withSuperFollowsTweetFields":True,"withSuperFollowsUserFields":True,"semantic_annotation_ids":[]},                     "features":{"view_counts_public_visibility_enabled":True,"view_counts_everywhere_api_enabled":True,"longform_notetweets_consumption_enabled":False,"tweetypie_unmention_optimization_enabled":True,"responsive_web_uc_gql_enabled":True,"vibe_api_enabled":True,"responsive_web_edit_tweet_api_enabled":True,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":True,"interactive_text_enabled":True,"responsive_web_text_conversations_enabled":False,"responsive_web_twitter_blue_verified_badge_is_enabled":True,"verified_phone_label_enabled":False,"standardized_nudges_misinfo":True,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":False,"responsive_web_graphql_timeline_navigation_enabled":True,"responsive_web_enhance_cards_enabled":False},"queryId":aa}
                                                    
                                        r=requests.post(f'https://twitter.com/i/api/graphql/{aa}/CreateTweet',timeout=60,json=pay,headers=head,cookies=cock)
                                    print(f'NAKRuTILI P {lol} {time.time()-st}')
                                    
                                    s.close()

                            
                            if farm:
                                if len(acppervi)>10:
                                    tototo=acppervi[-random.randint(7,10):]
                                else:
                                    tototo=acppervi
                                ano=[15,20]
                                ano2=[80,120]
                            else:
                                if len(acppervi)>5:
                                    tototo=acppervi[-5:]
                                else:
                                    tototo=acppervi
                                ano=[1,7]
                                ano2=[5,9]

                                # if len(acppervi)>1:
                                #     tototo=acppervi[-1:]
                                # else:
                                #     tototo=acppervi
                                # ano=[2,2]
                                # ano2=[1,1]


                            tototoska=[]
                            for piska in tototo:
                                pl=piska.split(':')[-2]
                                try:
                                    int(pl)
                                    tototoska.append(pl)
                                except:
                                    pass
                                
                            cock=s.cookies.get_dict()

                            follow_list=[]
                            post_list=[]
                            if default:
                                asdff='_def'
                            else:
                                asdff=''
                            with open(f'farm_ids{asdff}.txt','r') as fol_acp:
                                fol_acp=fol_acp.readlines()
                            fol_acp2=[]
                            for accs in fol_acp:
                                fol_acp2.append(accs.replace('\n',''))
                            fol_acp=fol_acp2

                            random.shuffle(fol_acp)

                            follow_list=fol_acp[:random.randint(ano[0],ano[1])]
                            
                            tototoska.extend(follow_list)
                            follow_list=tototoska

                            if farm==False:
                                random.shuffle(follow_list)
                            


                            print('starting farm')
                            
                            with open(f'posts{asdff}.txt','r') as posts:
                                posts=posts.readlines()

                            random.shuffle(posts)
                            post_lists2=posts[:randint(ano2[0],ano2[1])]
                            post_list=[]
                            for kik in post_lists2:
                                post_list.append(kik.split(':')[-1].replace('\n',''))

                            if True:
                                try:
                                    tt=threading.Thread(target=farm_f, args=(follow_list,head,cock,s,lol,))
                                    tt.start()

                                    tt=threading.Thread(target=farm_post, args=(post_list,head,cock,s,lol,))
                                    tt.start()
                                except Exception as x:
                                    print(repr(x))

                            def farm_followers(uidm,tst=0):
                                with lock:
                                    with open('farm_followers.txt','r') as fap:
                                        fap=fap.readlines()
                                head={}
                                head['User-Agent']=ua=f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'
                                                    
                                head['Connection']= 'close'
                                head["authorization"]='Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA' 
                                        
                                global trap
                                for ggg in range(1):
                                    time.sleep(tst)
                                    print(trap,'trap')
                                    with lock:
                                        cookies=fap[trap].replace('\n','')
                                        cc={}
                                        cookies=cookies.split('; ')
                                        for cock in cookies:
                                            cc[cock.split('=')[0]]=cock.split('=')[-1]

                                        cookies=cc

                                        try:
                                            head['x-csrf-token']=cookies['ct0']
                                        except:
                                            pass    
                                        trap+=1
                                        trap=trap%len(fap)

                                    follow(head,uidm,cookies)
                            if False:

                                tt=threading.Thread(target=farm_followers,args=(uidm,))
                                tt.start()
                        else:
                            defik=True

                        s.get(f'https://twitter.com/{lol}',headers=head,timeout=15,proxies=proxy)
                        if do_phone and not defik:
                            try:
                                dp,phone=add_phone_cunt(head,s.cookies.get_dict(),password)
                            except Exception as x:
                                dp=False
                                print(repr(x))
                        else:
                            dp=False

                        if dp:
                            
                            print('DONE phone DONE',lol,password,mail)
                        else:      
                            print('DONE',lol,password,mail)
                        

                        donede+=1
                        prev=uidm
                        if dp:
                            with lock:
                    
                                    with open(f'create_and_unban_SYSTEM/{systemn}/create_phone.txt','a') as cpw:
                                        cpw.write(f"{lol}:{password}:{MAIL}:{MPASS}:{phone}:{ua}:{s.cookies.get_dict()}:{uidm}:{time.time()}\n")
                        else:
                            with lock:
                                if defik:
                                    with open(f'create_and_unban_SYSTEM/{systemn}/create_empty.txt','a') as cpw:
                                        cpw.write(f"{lol}:{password}:{MAIL}:{MPASS}:{ua}:{s.cookies.get_dict()}:{uidm}:{time.time()}\n")
                                else:
                                    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','a') as cpw:
                                        cpw.write(f"{lol}:{password}:{MAIL}:{MPASS}:{ua}:{s.cookies.get_dict()}:{uidm}:{time.time()}\n")
                        #ersin=0
                        if ersin>0:
                            ersin-=1
                        tocr-=1
                except Exception as x:

                    try:
                        print(repr(x))
                    except:
                        print('pizdec error')
                    ersin+=1
                finally:

                    try:
                        s.close()
                    except:
                        pass


                    if repmail:
                        with lock:
                            with open(f'create_and_unban_SYSTEM/mails.txt','a') as acpmaw:
                                acpmaw.writelines(towakas)
                    print(ersin,'ersin')
                    #print(proxy_id)#
                    #input('?')

            
        
        #ersin=0
        def launch(proxystr):
            alg=[]  
            proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}",
                                                                                        #"http" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
            for kish in range(odnovrem_t):
                gf=threading.Thread(target=main_create,args=(kish,proxys,proxystr,))
                gf.start()
                alg.append(gf)
            
            for i in alg:
                i.join()

        proxystr='s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
        #proxystr='pproxy.space:15235:eSAg3e:YmYgEPYD6Um3'   
        proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}",
                                                                                        #"http" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
        if False:
            alg=[]
            for kish in range(odnovrem_t):
            #for kish in range(1):
                if False:
                    if False:
                        while True:
                            try:
                                pay={"name":"1","type_id":1,"method_rotate":None,"timeout":None,"auth_type_id":1,"country_code":"US","state":None,"city":None,"asn":None,"proxy_type_id":1,"id":1}
                                try:
                                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                                    #print(r.text)
                                    passp=r.json()['data']['password']
                                except:
                                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=H3BzIzmNohD9hHkH6WjemN9DDMCKS76OIjDKx6TviNck4jfJV60R2uDLphRmJON9',json=pay)
                                    #print(r.text)
                                    passp=r.json()['data']['password']
                                if passp==None:
                                    passp=''
                                else:
                                    passp=str(passp)
                                proxystr=str(r.json()['data']['server'])+":"+str(r.json()['data']['port'])+":"+str(r.json()['data']['login'])+":"+passp

                                proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
                                # proxys={
                                #                                                         "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                #                                                 }
                                break    
                            except Exception as x:
                                print(repr(x))
                                time.sleep(3)   
                                                            
                    else:

                        if False:
                            r=requests.post('https://dashboard.iproyal.com/api/residential/royal/reseller/access/generate-proxy-list',data={'rotation':'sticky','username':'twitus','password':'twituspassos202','proxyCount':3,'lifetime':'15m'},headers={'X-Access-Token':'Bearer ynoxaJb8zyK2RH3IfnUvmLe4I9Cg8xNrlufJKnV0rcvMYkJwr8sNgviC2QEK','Content-Type': 'application/json'})
                            print(r.text)
                            proxylist=r.json()
                            
                            proxystr=proxylist.split('\n')[i]
                        else:
                            
                            proxystr=proxylist[0]
                            proxylist=proxylist[1:]
                            print(proxystr)
                            
                            
                        try:
                            proxys={
                                                                                                "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                        }
                        except:
                            proxys={
                                    "https" : f"https://{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                            }
                elif False:
                    zxc=0
                    cu=f'tw{systemn}_{kish}'
                    while True:
                        #print(1)
                        por=None
                        did=False
                        try:
                            headers={'authorization': 'Bearer 94415|H5DlVCS31tlsk9wOPrgjrBcjRLXHHMtJzChCZxoh',
                                    'cookie': '_ga=GA1.1.1522144765.1675091991; _gcl_au=1.1.1516374260.1675091991; _fbp=fb.1.1675091993191.1210132498; cf_clearance=sUAjEcFbEgPhQpemTBQWudKt0biH6QtBzS.9D.X4M2M-1675096050-0-150; token=94415%7CH5DlVCS31tlsk9wOPrgjrBcjRLXHHMtJzChCZxoh; footprints=eyJpdiI6IkF5N3BTVUJPZndyRm03ZTBZS0piSEE9PSIsInZhbHVlIjoiNEhrOHM5Ymk1V1U4ZVp3S3daUWtjYlNiRmQyclQ3NC9GQ0ZjUEFFVHU5Q1VRY3A1dWF5NkRvNGZQMDBmME1NK3dLTm1YaFl0RmU4Q3VHTDkxZDdlS1JvY0Nja0hNMEpOVmhHYzBwR2VRQ3h0dG5KaTRDT3JpckprTTJrY0Y5OG4iLCJtYWMiOiI0ZWYxNWY5MThjNDQ1MTExMzVjZjU2Yjc4MWUyOTU0ZmY4YjQzZWY4MDk5MWU4MGFjNWY5YWM4NmM2NDViMDMyIiwidGFnIjoiIn0%3D; _ym_uid=1675096070102023808; _ym_d=1675096070; _vid_t=2VS0dlX0V5wJExs0KMw4zu1Qkegs9LvGFr7wHUzU1acG2tq6jbdgGglYsc/2BdHTGvsr3eNOt1Ag6Q==; referral=LxR6NI; _ym_isad=2; _ym_visorc=w; _ga_LF32WD6QBF=GS1.1.1680624036.34.1.1680627464.0.0.0; asocks_session=eyJpdiI6IjFqSkFkVUdEQXM1amsrYTR1cjV5MHc9PSIsInZhbHVlIjoid3VQMTEwMFpERHhweWVXYmFCMll5OTBYSnhoekpZdW1JZHI0RHJqclZlZTIxMUgxZ2MzaU5yR2ptSmFQQVpMYVgwZEFwWCs4eEJFNjdzcHNHR1VKZk55Y3JTa3pzSXR4ZlhUYUtsNS90eDBMWjVFZUhNSW1HVDZKdUQ0THZWdUIiLCJtYWMiOiIxNDI0MTczZTMyMmQ0NDg4MDQ1ZDRjNjZlOWM2MDU3YmQyMWUyODFiYzM3OThlMTBkYmQ2OGE3OTg2MWZiYjI3IiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IkhkdFNHSTV6UHFORGF1OC9Oc2V3bnc9PSIsInZhbHVlIjoiMXVhVXUrOFhCTGwyL3pLRHJnbGM3bFdHQU9TVXR1RFk1TFRFYm83WXpMd3pDN0hZeFgzNWFaVzNzZFlrK3FwVWJtSzNBZXByaDZZdmJ1cXQ5VVdjOXlLREY0YVhNK1k3UStNSy8vOWxFTm9rUWNxVXlEMmM3S3RoZzRIUmhPYVgiLCJtYWMiOiJhNzQyZGRhODNiOGY5Njk3YTg2MzNjMmY3OWMxMzVkMmExNjA0Yjg5MDAxMTM1YzkwZGRmYTA3MWViNTE2N2U2IiwidGFnIjoiIn0%3D',
                                    'user-agent': #'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36'
                                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
                                    }

                            if False:
                                r=requests.get('https://api.asocks.com/api/v1/user/userProxy?page=1&group=1&perpage=1000',headers=headers,timeout=5)
                                #print(2)
                                for i in r.json()['data']:
                                    if i['name']==cu:
                                        did=i['id']
                                        break
                                #print(3)
                                if did:
                                    rr=requests.delete(f'https://api.asocks.com/api/v1/user/userProxy/{did}',headers=headers,timeout=5)

                                    print('deleted')
                            
                                break
                            else:
                                
                                r=requests.get('https://api.asocks.com/api/v1/user/userProxy?page=1&group=1&perpage=1000',headers=headers,timeout=5)
                                for i in r.json()['data']:
                                    if i['name']==cu:
                                        por=i['id']
                                        break
                                if por:             
                                    r=requests.get(f'https://api.asocks.com/v2/proxy/refresh/{por}?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp',timeout=5)
                                    print(r)
                                    print('changed')
                                break
                        except Exception as x:
                            if zxc>0:
                                break
                            zxc+=1
                            print(repr(x),'delete_proxy')
                            time.sleep(3)
                    
                    while True:
                        try:
                            if por:
                                r=requests.get('https://api.asocks.com/api/v1/user/userProxy?page=1&group=1&perpage=1000',headers=headers,timeout=5)
                                for i in r.json()['data']:
                                    if i['name']==cu:
                                        proxystr=str(i['server'])+":"+str(i['port'])+":"+str(i['login'])+":"+str(i['password'])

                                proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
                                break

                            else:
                                rtg=[]
                                try:
                                    rfd=requests.get('https://api.asocks.com/v2/dir/countries?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp')
                                    for jiji in rfd.json()['countries']:
                                        rtg.append(jiji['code'])

                                except Exception as zxc:
                                    print(repr(zxc))
                                    rtg=["BR",'DE','SA']

                                pay={"name":cu,"type_id":1,"method_rotate":None,"timeout":None,"auth_type_id":1,"country_code":'',"state":None,"city":None,"asn":None,"proxy_type_id":2,"id":1}
                                try:
                                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp',json=pay,timeout=15)
                                    #print(r.text)
                                    passp=r.json()['data']['password']
                                except:
                                    r=requests.post('https://api.asocks.com/v2/proxy/create-port/?apikey=YgbfwPePrTk8n6s6rpVYvXVMWspfodOS9kOPB9Z5sASTUFqfNqKuNHA14J25TSHp',json=pay,timeout=15)
                                    #print(r.text)
                                    passp=r.json()['data']['password']
                                if passp==None:
                                    passp=''
                                else:
                                    passp=str(passp)
                                proxystr=str(r.json()['data']['server'])+":"+str(r.json()['data']['port'])+":"+str(r.json()['data']['login'])+":"+passp

                                proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
                                # proxys={
                                #                                                         "socks5" : f"socks5://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                #                                                 }
                                print('created')
                                break 
                        except Exception as x:
                            print(repr(x),'get_proxy')
                            time.sleep(3)   

                elif True:
                    proxystr='s7.op-proxy.com:23006:vS1KUiagymemm7yO2:PwLiAIB76kGfweH'
                    #proxystr='pproxy.space:15235:eSAg3e:YmYgEPYD6Um3'   
                
                    # proxys={
                    #                                                                         "http" : f"http://{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                    #                                                                 }
                    proxys={
                                                                                        "https" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}",
                                                                                        #"http" : f"https://{proxystr.split(':')[2]}:{proxystr.split(':')[3]}@{proxystr.split(':')[0]}:{proxystr.split(':')[1]}"
                                                                                }
                    
                proxy=proxys
                #input('STARTUEM WARNING?  - ')
                gf=threading.Thread(target=main_create,args=(kish,proxy,proxystr,))
                gf.start()
                alg.append(gf)
            
            for i in alg:
                i.join()
        else:
            launch(proxystr)

      

    print('SYSTEM START')
    #SYSTEM
    def doubles():
        
        lock = threading.Lock()
        with lock:
            w_create=[]
            w_req=[]
            w_repl=[]
            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
                acp_create=acp_create.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
                acp_requested=acp_requested.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
                acp_replied=acp_replied.readlines()


            for hui in acp_create:
                notd=True
                for jh in w_create[::-1]:
                    if ":".join(hui.split(':')[0:2]) in jh:
                        notd=False
                        break
                if notd:
                    w_create.append(hui)

            for hui in acp_requested:
                notd=True
                for jh in w_req[::-1]:
                    if ":".join(hui.split(':')[0:2]) in jh:
                        notd=False
                        break
                if notd:
                    w_req.append(hui)

            for hui in acp_replied:
                notd=True
                for jh in w_repl[::-1]:
                    if ":".join(hui.split(':')[0:2]) in jh:
                        notd=False
                        break
                if notd:
                    w_repl.append(hui)


            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acp_create:
                acp_create.writelines(w_create)

            with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','w') as acp_requested:
                acp_requested.writelines(w_req)

            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','w') as acp_replied:
                acp_replied.writelines(w_repl)
    
    doubles()
    #input("NEST?")
    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
        acp_create=acp_create.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
        acp_requested=acp_requested.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
        acp_replied=acp_replied.readlines()



    print(len(acp_create),len(acp_requested),len(acp_replied))
    print('CHECK VALID')
    #CHECK VALID
    
    w_create=acp_create[:]
    w_req=acp_requested[:]
    w_repl=acp_replied[:]
    a_not403=[]
    a_mailban=[]
    sending_mail_req=0
    sending_mail_rep=0

    def check_mail(a1,a2,acpsh,ac,ts):
        global sending_mail_req
        global sending_mail_rep
        global w_create
        global w_repl
        global w_req
        global a_not403
        global ersin
        global a_mailban
        global total_to_req_again

        if 'requested' in ac:
        #if True:
            while sending_mail_req>=2:
                time.sleep(1)
        else:
            while sending_mail_rep>=2:
                time.sleep(1)

        if 'requested' in ac:        
            sending_mail_req+=1
        else:
            sending_mail_rep+=1

        for i in range(a1,a2):
            try:
                fa=acpsh[i]
                t=True
            except Exception as x:
                #print(repr(x))
                t=False

            try:
                ctm=float(fa.split(':')[-1].replace('\n',''))
            except:
                ctm=1234.1234

            if t and 'replied' in ac:
                if time.time()-ctm>3*60*60*24 :
                    t=True
                else:
                    t=False

            if t:
                time.sleep(ts)
                try:
                    head,mm,cookies=system_check_start(fa)

                    #tex=gen_appeal_tex()
                    tex=''
                    body = f'''{tex}'''
                    body_html = f'''<p>{tex}</p>'''

                    MAIL=fa.split(':')[2]
                    MPASS=fa.split(':')[3]
                    if 'replied' in ac:
                        cat='replied'
                    else:
                        cat='requested'
                    zxc=0
                    while True:
                        try:
                            #sb=mm.delete_or_repply(MAIL,MPASS,cat,body,body_html,proxysocks,float(fa.split(':')[-1].replace('\n','')))
                            
                            sb=mm.delete_or_repply(MAIL,MPASS,cat,body,body_html,None,float(fa.split(':')[-1].replace('\n','')))
                            
                            break
                        except Exception as asdf:
                            print(repr(asdf),'repply 1',fa.split(':')[2])
                            time.sleep(2)
                            zxc+=1
                            if zxc>3:
                                raise Exception(asdf)

                    if sb==None: #RAZBANILI NO SUD9 PO VSEMY SNOVA BAN => REQUEST AGAIN
                        print('RAZBANILI NO SUD9 PO VSEMY SNOVA BAN => REQUEST AGAIN',fa.split(':')[0])
                        #mm.delete(MAIL,MPASS)
                        # to_req.append(fa)

                        #input(f'del? {MAIL} {MPASS}')
                        mm.delete(MAIL,MPASS)
                        #if cat=='replied':
                

                            ###EDIT
                        
                        try:
                            float(fa.split(':')[-1].replace('\n',''))
                            accc=fa.split(':')
                            accc[-1]=f"{123}\n"
                            fa=':'.join(accc)
                        except Exception as x:
                            print(repr(x))
                            print(f'FLOAT ERROR {fa.split(":")[0]}')
                            fa=fa

                        tocrackwrite=[fa]
                        total_to_req_again+=1


                        with lock:
                            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acpdnr:    
                                acpdnr=acpdnr.readlines()

                            tocrackwrite.extend(acpdnr)
                            

                            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acpdn:    
                                acpdn.writelines(tocrackwrite)

                        
                            with open(f'{ac}.txt','r') as acpch:       
                                acp2=acpch.readlines()

                            acptw=acp2
                            while True:
                                try:
                                    acptw.remove(fa)
                                except:
                                    break
                            
                            with open(f'{ac}.txt','w') as acpch:        
                                acpch.writelines(acptw)
                                print(len(acptw))



                    elif sb==True:
                        print(f'FOUND EMAIL AND REPLIED {fa.split(":")[2]}')    
                        # mm.delete(MAIL,MPASS)

                        try:
                            float(fa.split(':')[-1].replace('\n',''))
                            accc=fa.split(':')
                            accc[-1]=f"{str(time.time())}\n"
                            acpnewi=':'.join(accc)
                        except Exception as x:
                            print(repr(x))
                            print(f'FLOAT ERROR {fa.split(":")[0]}')
                            acpnewi=fa





                        with lock:
                            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','a') as acpdn:    
                                acpdn.write(acpnewi)

                        
                            with open(f'{ac}.txt','r') as acpch:       
                                acp2=acpch.readlines()

                            acptw=acp2
                            while True:
                                try:
                                    acptw.remove(fa)
                                except:
                                    break
                            
                            with open(f'{ac}.txt','w') as acpch:        
                                acpch.writelines(acptw)
                                    


                    elif sb=='deliv_fail':
                        print("ERROR DELIV FAIL ",fa.split(':')[2])
                        while True:
                            try:
                                w_repl.remove(fa)
                            except:
                                break
                        while True:
                            try:
                                w_req.remove(fa)
                            except:
                                break
                        #input(f'del? {MAIL} {MPASS}')
                        mm.delete(MAIL,MPASS)
                        #if cat=='replied':
                        
                        ###EDIT
                        
                        try:
                            float(fa.split(':')[-1].replace('\n',''))
                            accc=fa.split(':')
                            accc[-1]=f"{123}\n"
                            fa=':'.join(accc)
                        except Exception as x:
                            print(repr(x))
                            print(f'FLOAT ERROR {fa.split(":")[0]}')
                            fa=fa

                        tocrackwrite=[fa]
                        total_to_req_again+=1
                        # if len(w_create)>1:    #??
                        #     tocrackwrite.extend(w_create)
                        # else:   #??
                        #     tocrackwrite.append(w_create)


                        with lock:
                            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acpdnr:    
                                acpdnr=acpdnr.readlines()
                                
                            tocrackwrite.extend(acpdnr)

                            

                            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acpdn:    
                                acpdn.writelines(tocrackwrite)

                        
                            with open(f'{ac}.txt','r') as acpch:       
                                acp2=acpch.readlines()

                            acptw=acp2
                            while True:
                                try:
                                    acptw.remove(fa)
                                except:
                                    break
                            
                            with open(f'{ac}.txt','w') as acpch:        
                                acpch.writelines(acptw)
                                        

                    elif sb=='MAILBAN':
                        

                        with lock:
                                with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as acpdn:    
                                    acpdn.write(fa)

                            
                                with open(f'{ac}.txt','r') as acpch:       
                                    acp2=acpch.readlines()

                                acptw=acp2
                                while True:
                                    try:
                                        acptw.remove(fa)
                                    except:
                                        break
                                
                                with open(f'{ac}.txt','w') as acpch:        
                                    acpch.writelines(acptw)
                                        

                        

                    elif sb=='FOREVER':
                       # if 'replied' in ac:

                        with lock:
                                with open(f'create_and_unban_SYSTEM/{systemn}/forever.txt','a') as acpdn:    
                                    acpdn.write(fa)

                            
                                with open(f'{ac}.txt','r') as acpch:       
                                    acp2=acpch.readlines()

                                acptw=acp2
                                while True:
                                    try:
                                        acptw.remove(fa)
                                    except:
                                        break
                                
                                with open(f'{ac}.txt','w') as acpch:        
                                    acpch.writelines(acptw)
                                        
                    else:
                        print(f"NO MAIL\nNO {fa.split(':')[2]}")

                except Exception as x:
                    if str(x)=='mail ban':
                        #if 'replied' in ac:
                        if False:
                            while True:
                                try:
                                    w_repl.remove(fa)
                                except:
                                    break

                            while True:
                                try:
                                    w_req.remove(fa)
                                except:
                                    break
                            a_mailban.append(fa)

                        else:
                            with lock:
                                    with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as acpdn:    
                                        acpdn.write(fa)

                                
                                    with open(f'{ac}.txt','r') as acpch:       
                                        acp2=acpch.readlines()

                                    acptw=acp2
                                    while True:
                                        try:
                                            acptw.remove(fa)
                                        except:
                                            break
                                    
                                    with open(f'{ac}.txt','w') as acpch:        
                                        acpch.writelines(acptw)
                                        print(len(acptw))

                        
                    print(repr(x),fa.split(":")[2])
                #input('?')

        if 'requested' in ac:        
            sending_mail_req-=1
        else:
            sending_mail_rep-=1

        #if 'requested' in ac:
        if True:
            global slowed
            slowed-=1
            print(slowed,'slow')
            if slowed<=0:
                slowed=-100



    def check_valid(a1,a2,acpsh,ac,ts=0):
        global w_create
        global w_repl
        global w_req
        global a_not403
        global ersin
        
        for i in range(a1,a2):
            
            try:
                fa=acpsh[i]
                t=True
            except Exception as x:
                #print(repr(x))
                t=False
            if t:
                try:
                    #head,mm,cookies=system_check_start(fa,False)
                    head,cookies=system_check_start(fa,False)        
                    if False:
                        uid=acpsh[i-1].split(':')[-2]
                        if uid.isdigit()==False:
                            uid=random.choice(['1381699264011771906','1415078650039443456','859011517','5863182','94261044'])
                    else:
                        #uid=random.choice(['1381699264011771906','1415078650039443456','859011517','5863182','94261044'])
                        with open('/root/work/farm_ids.txt','r') as fid:
                            fid=fid.readlines()
                        uid=random.choice(fid)
                        uid=uid.replace('\n','')

                    if False:
                        rf=follow(head,uid,cookies)
                        #rf=check(fa.split(':')[0],ts)
                    else:
                        rf=twit(head,cookies)

                    # try:
                    #     print(rf.text) 
                    # except:
                    #     print(rf)

                    if type(rf)==Boolean: 
                        #print('WARNING CHE ZA HUINA ERROR')
                        if rf==True:
                            dfv=False

                        elif rf==False:
                            dfv=True
                    else:
                        if 'Missing TwitterUserNotSuspended' in rf.text or 'temporarily locked' in rf.text or 'Your account is suspended' in rf.text:
                            dfv=True
                        else:
                            dfv=False

                    try:
                        if rf.status_code==200:
                            dfv=False
                    except:
                        pass

                    #if 'Missing TwitterUserNotSuspended' in rf.text or 'temporarily locked' in rf.text or 'Your account is suspended' in rf.text:
                    if dfv==True:
                        
                        # print(head)
                        # print(cookies)
                        try:
                            #{"id":1471563114101497868,"id_str":"1471563114101497868","name":"Austin Scholar","screen_name":"AustinScholar","location":"Austin, TX","description":"Teen at a high school with no teachers. Writing about education & how to help your kid thrive. I tell you what your teen is thinking so you don't have to guess.","url":"https:\/\/t.co\/znfe3OZgNP","entities":{"url":{"urls":[{"url":"https:\/\/t.co\/znfe3OZgNP","expanded_url":"http:\/\/austinscholar.substack.com","display_url":"austinscholar.substack.com","indices":[0,23]}]},"description":{"urls":[]}},"protected":false,"followers_count":4292,"fast_followers_count":0,"normal_followers_count":4292,"friends_count":167,"listed_count":63,"created_at":"Thu Dec 16 19:29:47 +0000 2021","favourites_count":1529,"utc_offset":null,"time_zone":null,"geo_enabled":false,"verified":false,"statuses_count":1188,"media_count":77,"lang":null,"contributors_enabled":false,"is_translator":false,"is_translation_enabled":false,"profile_background_color":"F5F8FA","profile_background_image_url":null,"profile_background_image_url_https":null,"profile_background_tile":false,"profile_image_url":"http:\/\/pbs.twimg.com\/profile_images\/1544734469092933633\/4bp2tCSO_normal.jpg","profile_image_url_https":"https:\/\/pbs.twimg.com\/profile_images\/1544734469092933633\/4bp2tCSO_normal.jpg","profile_banner_url":"https:\/\/pbs.twimg.com\/profile_banners\/1471563114101497868\/1673383753","profile_link_color":"1DA1F2","profile_sidebar_border_color":"C0DEED","profile_sidebar_fill_color":"DDEEF6","profile_text_color":"333333","profile_use_background_image":true,"has_extended_profile":true,"default_profile":true,"default_profile_image":false,"pinned_tweet_ids":[1626706736890494977],"pinned_tweet_ids_str":["1626706736890494977"],"has_custom_timelines":false,"can_dm":null,"can_media_tag":true,"following":false,"follow_request_sent":false,"notifications":false,"muting":false,"blocking":false,"blocked_by":false,"want_retweets":false,"advertiser_account_type":"none","advertiser_account_service_levels":[],"profile_interstitial_type":"","business_profile_state":"none","translator_type":"none","withheld_in_countries":[],"followed_by":false,"ext_has_nft_avatar":false,"ext_is_blue_verified":true,"require_some_consent":false}
                            if rf.text!=r'{"errors":[{"code":64,"message":"Your account is suspended and is not permitted to access this feature."}]}' and rf.text!=r'{"errors":[{"code":326,"message":"To protect our users from spam and other malicious activity, this account is temporarily locked. Please log in to https://twitter.com to unlock your account.","sub_error_code":0,"bounce_location":"https://twitter.com/account/access"}]}':
                                try:
                                    print(rf)
                                    #print(rf.status_code)
                                    print(rf.text,fa.split(":")[0])
                                except:
                                    print(f'NEOBICHNII 403 {fa.split(":")[0]}')
                                    if 'temporarily locked' in rf.text or 'Missing TwitterUserNotSuspended' in rf.text:
                                        print(True,fa.split(":")[0])
                                    else:
                                        print(False,fa.split(":")[0])
                        except:
                            pass
                        print('ERROR 403',fa.split(':')[0]) 


                    else:
                        print('DONE F',fa.split(":")[0])
                        try:
                            float(fa.split(':')[-1].replace('\n',''))
                            accc=fa.split(':')
                            accc[-1]=f"{str(time.time())}\n"
                            acpnewi=':'.join(accc)
                        except Exception as x:
                            print(repr(x))
                            print(f'FLOAT ERROR {fa.split(":")[0]}')
                            acpnewi=fa

                        MAIL=fa.split(':')[2]
                        MPASS=fa.split(':')[3]
                        #mm.delete(MAIL,MPASS)
                        global aki
                        aki.append([MAIL,MPASS])
                        if True:
                            with lock:
                                with open(f'create_and_unban_SYSTEM/{systemn}/not403.txt','a') as acpdn:    
                                    acpdn.write(acpnewi)

                            
                                with open(f'{ac}.txt','r') as acpch:       
                                    acp2=acpch.readlines()

                                acptw=acp2
                                acptw.remove(fa)
                                
                                with open(f'{ac}.txt','w') as acpch:        
                                    acpch.writelines(acptw)
                                    print(len(acptw))
                        # else:
                        #     a_not403.append(acpnewi)
                            while True:
                                try:
                                    w_repl.remove(fa)
                                except:
                                    break
                            while True:
                                try:
                                    w_req.remove(fa)
                                except:
                                    break

                except Exception as x:

                    if str(x)=='mail ban':
                        while True:
                            try:
                                w_repl.remove(fa)
                            except:
                                break
                        while True:
                            try:
                                w_req.remove(fa)
                            except:
                                break

                        a_mailban.append(fa)
                    print(repr(x),fa.split(':')[0])

    
    
    for dodo in [check_valid]:
        gnum2=500
        if dodo==check_mail:
            gnum2=100
        
        for acpshn in range(2):

            

            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
                acp_create=acp_create.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
                acp_requested=acp_requested.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
                acp_replied=acp_replied.readlines()

            acpsh=[acp_replied[:],acp_requested[:]][acpshn]
            ac=[f'create_and_unban_SYSTEM/{systemn}/replied',f'create_and_unban_SYSTEM/{systemn}/requested'][acpshn]

            ccc=len(acpsh)//gnum2+1
            alt=[]
            print(ac)

            w_create=acp_create[:]
            w_req=acp_requested[:]
            w_repl=acp_replied[:]
            if 'requested'  in ac and dodo==check_mail:
                print('SKIP SKIP SKIP')
            else:
                for cjh in range(0,gnum2):
                    print(ccc*cjh,(ccc*(cjh+1)))
                    
                    tt=threading.Thread(target=dodo, args=(ccc*cjh,(ccc*(cjh+1)),acpsh,ac,cjh,))
                    tt.start()
                    if dodo==check_mail:
                        time.sleep(0.01)
                    alt.append(tt)


            for tt in alt:
                #tt.start()
                tt.join()

            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acp_create:
                acp_create.writelines(w_create)

            with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','w') as acp_requested:
                acp_requested.writelines(w_req)

            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','w') as acp_replied:
                acp_replied.writelines(w_repl)


            with open(f'create_and_unban_SYSTEM/{systemn}/not403.txt','a') as acp_not403:
                acp_not403.writelines(a_not403)
            with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as acp_mailban:
                acp_mailban.writelines(a_mailban)

            print(len(w_create),len(w_req),len(w_repl),len(a_not403))
            for im in a_not403:
                print(im.split(':')[0],end=', ')
            #print(a_not403)
            a_not403=[]
            a_mailban=[]

            
            #print(proxy_id)#
        #input(f'{dodo} {ac} ?')

        




        
        print(f'WARNING starting deleting recoverable items {len(aki)}')
        mka=mmail.dop_deiv()    
        erkas=mka.delete_rec(aki)
        aki=[]
        



    print(total_to_req_again,'total_to_req_again')

    ####
    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
        acp_create=acp_create.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
        acp_requested=acp_requested.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
        acp_replied=acp_replied.readlines()
    ####




    ###
    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acpdn:    
        acpdn=acpdn.readlines()

    print('do')
    print(len(acp_create))
    print(len(acp_requested))
    print(len(acp_replied))
    
    toded=[]
    for rer in acpdn:
        try:
            tit=float(rer.split(':')[-1].replace('\n',''))
        except:
            tit=1234.1234
        if tit+10*60*60*24<time.time():
            
            with lock:
                total_to_req_again+=1
                rerold=rer
                try:
                    float(rer.split(':')[-1].replace('\n',''))
                    accc=rer.split(':')
                    accc[-1]=f"{123}\n"
                    rer=':'.join(accc)
                except Exception as x:
                    print(repr(x))
                    print(f'FLOAT ERROR {rer.split(":")[0]}')
                    rer=rer

                toded.append(rer)
                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as crack:    
                    crack=crack.readlines()
                tocrackwrite=[rer]

                # if len(crack)>1:    #??
                #     tocrackwrite.extend(crack)
                # else:   #??
                #     tocrackwrite.append(crack)  #??
                tocrackwrite.extend(crack)

                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acpdnch:    
                    acpdnch.writelines(tocrackwrite)

                with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acpch:       
                    acp2=acpch.readlines()

                acptw=acp2
                acptw.remove(rerold)
                
                with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','w') as acpch:        
                    acpch.writelines(acptw)


    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acpdn:    
        acpdn=acpdn.readlines()

    for rer in acpdn:
        try:
            tit=float(rer.split(':')[-1].replace('\n',''))
        except:
            tit=1234.1234

        if tit+30*60*60*24<time.time():
            with lock:
                total_to_req_again+=1
                rerold=rer
                try:
                    float(rer.split(':')[-1].replace('\n',''))
                    accc=rer.split(':')
                    accc[-1]=f"{123}\n"
                    rer=':'.join(accc)
                except Exception as x:
                    print(repr(x))
                    print(f'FLOAT ERROR {rer.split(":")[0]}')
                    rer=rer
                toded.append(rer)
                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as crack:    
                    crack=crack.readlines()
                tocrackwrite=[rer]

                # if len(crack)>1:    #??
                #     tocrackwrite.extend(crack)
                # else:   #??
                #     tocrackwrite.append(crack)  #??
                tocrackwrite.extend(crack)

                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acpdnch:    
                    acpdnch.writelines(tocrackwrite)

                with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acpch:       
                    acp2=acpch.readlines()

                acptw=acp2
                acptw.remove(rerold)
                
                with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','w') as acpch:        
                    acpch.writelines(acptw)

    def delaha(a1,a2,acpsh):
        global w_create
        global w_repl
        global w_req
        global a_not403
        global ersin
        global a_mailban
        global total_to_req_again
        for i in range(a1,a2):
            try:
                rer=acpsh[i]
                t=True
            except Exception as x:
                #print(repr(x))
                t=False
            if t:
                try:
                    MAIL=rer.split(':')[2]
                    MPASS=rer.split(':')[3]
                    if '@gmx' in MAIL:
                        typegh='gmx'
                    elif '@gmail' in MAIL:
                        typegh='gmail'
                    elif '@outlook' in MAIL or '@hotmail' in MAIL:
                        typegh='hot'
                    elif '@mail' in MAIL:
                        typegh='mail'
                    elif '@rambler' in MAIL or '@ro.ru' in MAIL:
                        typegh='rambler'
                    try:
                        mm=mmail.mail_by_login(MAIL,MPASS,typegh)
                    except Exception as x:
                        if 'KeyboardInterrupt' in str(x):
                            dn='KeyboardInterrupt'
                            raise Exception('KeyboardInterrupt')
                        else:
                            print(repr(x))
                            while True:
                                try:
                                    w_repl.remove(rer)
                                except:
                                    break

                            while True:
                                try:
                                    w_req.remove(rer)
                                except:
                                    break
                            a_mailban.append(rer)

                    mm.delete(MAIL,MPASS)
                    print(MAIL,'deleted')
                except Exception as x:
                    print(repr(x),rer.split(':')[2])

    gnum2=100
    ccc=len(toded)//gnum2+1
    alt=[]

    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
        acp_create=acp_create.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
        acp_requested=acp_requested.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
        acp_replied=acp_replied.readlines()

    w_create=acp_create[:]
    w_req=acp_requested[:]
    w_repl=acp_replied[:]

    print("DELAHA WARNING")
    for cjh in range(0,gnum2):
        print(ccc*cjh,(ccc*(cjh+1)))
        tt=threading.Thread(target=delaha, args=(ccc*cjh,(ccc*(cjh+1)),toded,))
        tt.start()
        alt.append(tt)


    for tt in alt:
        #tt.start()
        tt.join()




    ###
    with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as acp_mm:
        acp_mm.writelines(a_mailban) 

    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acp_create:
        acp_create.writelines(w_create)

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','w') as acp_requested:
        acp_requested.writelines(w_req)

    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','w') as acp_replied:
        acp_replied.writelines(w_repl)


    ###
    ####
    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
        acp_create=acp_create.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
        acp_requested=acp_requested.readlines()

    with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
        acp_replied=acp_replied.readlines()
    ####

    print(total_to_req_again,'total_to_req_again')

    print('posle')
    print(len(acp_create))
    print(len(acp_requested))
    print(len(acp_replied))

    #SEND REQUEST
    print('SEND REQUEST')
    ersin2=0
    localsystemn=str(global_dop_system[0])
    global_dop_system=global_dop_system[1:]

    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','a') as acp_create2:
        acp_create2.writelines(acp_create[:-100])
        #acp_create2.writelines(acp_create[:5])

    with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acp_createt:
        acp_createt.writelines(acp_create[-100:])    
        #acp_createt.writelines(acp_create[5:])    



    #if do_phone:
    if False:
        with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','r') as acp_allc:
            acp_allc=acp_allc.readlines()

        with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','w') as acp_allcw:
            acp_allcw.writelines(acp_allc[:-150])

        with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/to_phone.txt','a') as acp_allcw:
            acp_allcw.writelines(acp_allc[-150:])
    
    # def unlock(cookies):
        
    #     s=requests.Session()
    #     for i in cookies:
    #         #if i!='ct0':
    #             s.cookies.set(i,cookies[i])
                
    #     rf=s.get('https://twitter.com/account/access',headers=head,timeout=10,proxies=proxy)
    #     aut=rf.text.split('name="authenticity_token" value="')[-1].split('">')[0]
    #     ast=rf.text.split('name="assignment_token" value="')[-1].split('">')[0]

    #     if False:
    #         js_chal=requests.get('https://twitter.com/i/js_inst?c_name=ui_metrics'
    #         ,timeout=10,proxies=proxy).text
    #                                 #print(len(js_chal))
    #         j_s=js_chal.split("'s':'")[-1].split("'};")[0]

    #         jj=js_chal.split("var ")[2].split("=")
    #         j_1=jj[0]
    #         j_12=jj[1].split(";")[0]

    #         jj=js_chal.split("var ")[3].split("=")
    #         j_2=jj[0]
    #         j_22=jj[1].split(";")[0]

    #         jj=js_chal.split("var ")[4].split("=")
    #         j_3=jj[0]
    #         j_32=jj[1].split(";")[0]

    #         jj=js_chal.split("var ")[5].split("=")

    #         j_4=jj[0]
    #         j_42=jj[1].split(";")[0]   

    #         metrics=f"{{\"rf\":{{\"{j_1}\":{j_12},\"{j_2}\":{j_22},\"{j_3}\":{j_32},\"{j_4}\":{j_42}}},\"s\":\"{j_s}\"}}"
    #         metricsu=urllib.parse.quote(metrics)
    #     elif False:
    #         r=s.get('https://twitter.com/account/access?js=1',proxies=proxy,headers=head,cookies=cookies)
    #         r=r.text
    #         r=r.split("$('.Button').prop('disabled', false);")[-1].split('};};')[0]+'};};'

    #         nan=r.split(' ')[1]
    #         r=r+f'{nan};'
    #         if True:
    #             tot=[]

                
    #             print(r)
    #             print(len(r))
    #             input('?')
    #             while len(r)>0:
    #                 if len(r)>700:
    #                     tot.append(r[:700])
    #                     r=r[700:]
    #                 else:
    #                     tot.append(r)
    #                     r=''   

    #             #print(len(tot))
    #             for hu in tot:
    #                 #print(hu,end='')
    #                 pass

    #             #input('?')
    #             tr=''
    #             for f in range(30):
    #                 try:
    #                     tw=tot[f]
    #                 except:
    #                     tw=''

    #                 tr=f"{tr}code{f+1}={tw}&"
    #                 #print(f"code{f+1}=tw&",end='')

    #             tr=tr[:-1]
    #             print('go')
    #             #cipher=requests.get(f'http://127.0.0.1:3000/getui?{tr}').text
    #             cipher=requests.get(f'http://127.0.0.1:3000/go').text

                

    #         elif True:
    #             with open(r'D:\Python_scripts\UNIQUE\rega\helper_cipher\OutLookHelperApi\file.js','w') as acpj:
    #                 acpj.write(r)
    #             response = muterun_js(r'D:\Python_scripts\UNIQUE\rega\helper_cipher\OutLookHelperApi\file.js')
                
    #             if response.exitcode == 0:
    #                 print(response.stdout)
    #                 cipher=response.stdout
    #             else:
    #                 sys.stderr.write(response.stderr)
    #             input('?')
            
    #     else:
    #         cipher='{"rf":{"e94790a4381989fea73ec377decc03efcfae3de8df0c051bcfecfa432c01c1ec":0,"e7561b707ddc9cd4ce999ebdd6f0ba561630440f80393e88155b2ba701ad6c56":-224,"f2689f1c04d99d70be5c756707283b3cabd424ab53e62b9ad259c39319cb255d":1,"acce1577afd267ee48e6ddc52f85635ff87e4e40362ea6de00ea6476723c1a0e":-1},"s":"BaKZOtgU9AtXYxKoxzNx4JKasJGgEOWxf_pRxcoVaMWhCztEpdCxRdkVk1bW_WuDF-UG1qpCglQIMAOMiQYQcGgX1VekFnzdE-aORKq1ijZQy9lEA6LC_-jQGdy4yJcoZX56cFWlCB0L1mGVlTQbh8gUWuUx4axBj1l6QAIQtQIWkzWFdd_HlMwvVzFqD0iYS8NWKIG0i8g8g_p-y6J6MbK86wl3krfNUXBBwS8vWZJfOBrWRsm5G-lA6Jb18bODHTf-vc9PWbxc0GkZMG3HhJ2-DYwSArIbEbSNFHl2Fs48Hpb0YI0cHvWkHNpIib7IzeNFx-LS5oHI9bZZtzTlAgAAAYeLP1I3"}'
            
    #     #metricsu=urllib.parse.quote(cipher)
    #     metricsu=cipher

    #     #print(metricsu)
    #     #input('?')

    #     pay=f'authenticity_token={aut}&assignment_token={ast}&lang=en&flow=&ui_metrics={metricsu}'
        
    #     payj={'authenticity_token':aut,
    #     "assignment_token":ast ,
    #     "lang": 'en',
    #     'flow':'',
    #     "ui_metrics": metricsu
    #     }
    #     #pay=f'authenticity_token={aut}&assignment_token={ast}&lang=en&flow=&ui_metrics=%7B%22rf%22%3A%7B%22a19a43b5caadbbb5262ac165f0808ebe5df43e65226575a9ba518102080ff0bb%22%3A175%2C%22a6a6cee0aebfcd44ac4bede02c9b32f186f30ded8d862834e6578a163fc4941f%22%3A134%2C%22adc94c39c0b581a889beb45a2b59675c1de30c9ba584613094650231e3ce6fa8%22%3A-25%2C%22aecdbdd2b729606a6ea8080e9a410fb19c24c2cc83d05a5c07a11eccb662bffa%22%3A152%7D%2C%22s%22%3A%222k4GhSKXOoTUMUy61768dbIEnwi5lVizWLxZphGOqDZk_kg_-GJOWntvNMWeAEN00k0CwXNe8u9XXOz5G-f1RMFZcjdrH05I5Hrup_rVRpFT-kcpZrzqvoW4w-0OfwNZHHxBI8GBPhImBW7zbiu82enNpawSwcpavaUng9q07_NbNvxIqUAO-kjjbYPLCrQ_hYptsSBkiCgXpYkgavLjH1heisIktyHCV1BcDHzudxCPUUNXNjUZLYQ015O7DENki9Rbi6bztroa8BYANlRTN_dEF4rR_9pZ7LnJRcfWpCm98wPFAnsHfQghWBHyL_9_dHDV7TSd0bk-KUsCew3SsgAAAYYmRiJG%22%7D'
        
    #     #{"rf":{"ce46e789472827f399199514a5c1d742996d71ccc4c7d700124c0b4e51747f8d":85,"acab61d449a83051f00d74fc7cc325ccc006db4dea035a37a4c166dc11895b3d":104,"c9a925113ab5677b55a1ffa9878e09d539597536d9fd9aaa4d3c9345f4a81491":77,"a824def5f5af5c27d168ed33ac5c4ce4120c894074fc1a7bc930c0ce966b897e":62},"s":"EBKD2M67n00kkM26n_v5W4E95qZm0mXbfA4P7_LAN74ylhkZXgmXa_Ruar9e-5scMjAwPq5QGwsygF3laFNvremC9USm6ieF875kQLC8lf5Ul43uiibnobJTWXxy9ljGqitcxvlVpNP6I-7E3P9IbRXR_2uwedNr9Jnpwe1fdxRo69kBAQTgaFN72sWlKsl940RXIwH3pkOxTT0JH5P6zvwR5V3ugjGSRnbU_dstd89tRh_T2O8XIed5tKKIJRvS5ZTJiTb7INc90WdjKDfJByRlYrlyRG7CYTnD0f4EPa9vlnTM-5hjUUYJILtnP0l65l6NvkFkDpxUSUiYqJ0BXgAAAYYnCkGI"}
    #     # {"rf":{"a19a43b5caadbbb5262ac165f0808ebe5df43e65226575a9ba518102080ff0bb":175,"a6a6cee0aebfcd44ac4bede02c9b32f186f30ded8d862834e6578a163fc4941f":134,"adc94c39c0b581a889beb45a2b59675c1de30c9ba584613094650231e3ce6fa8":-25,"aecdbdd2b729606a6ea8080e9a410fb19c24c2cc83d05a5c07a11eccb662bffa":152},"s":"2k4GhSKXOoTUMUy61768dbIEnwi5lVizWLxZphGOqDZk_kg_-GJOWntvNMWeAEN00k0CwXNe8u9XXOz5G-f1RMFZcjdrH05I5Hrup_rVRpFT-kcpZrzqvoW4w-0OfwNZHHxBI8GBPhImBW7zbiu82enNpawSwcpavaUng9q07_NbNvxIqUAO-kjjbYPLCrQ_hYptsSBkiCgXpYkgavLjH1heisIktyHCV1BcDHzudxCPUUNXNjUZLYQ015O7DENki9Rbi6bztroa8BYANlRTN_dEF4rR_9pZ7LnJRcfWpCm98wPFAnsHfQghWBHyL_9_dHDV7TSd0bk-KUsCew3SsgAAAYYmRiJG"}
        
        

        
    #     cookies=s.cookies.get_dict()
    #     s=requests.Session()
    #     for i in cookies:
    #         # if i!='ct0':
    #         #     s.cookies.set(i,cookies[i])
    #         if i=='_twitter_sess': #or i=='auth_token': #or i=='kdt':
    #             s.cookies.set(i,cookies[i])
    #     # print(s.cookies.get_dict())
    #     # print(pay)
    #     # print(head)

    #     rf=s.post('https://twitter.com/account/access',data=payj,timeout=10,proxies=proxy,cookies=cookies,headers=head)
    #     #print(rf.text)
    #     print(rf) 
            
        

    #     while True:
    #         token=input('token ? - ')
    #         pay=f"authenticity_token={aut}&assignment_token={ast}&lang=en&flow=&verification_string={token}&language_code=en"

    #         pay={
    #             'authenticity_token': aut,
    #             'assignment_token':ast,
    #             'lang': 'en',
    #             'flow': '',
    #             'verification_string': token,
    #             'language_code': 'en'

    #         }
    #         rf=s.post('https://twitter.com/account/access?lang=en',data=pay,headers=head,timeout=10,proxies=proxy,cookies=cookies)
            
    #         if 'Account unlocked.' in rf.text:
    #             aut=rf.text.split('name="authenticity_token" value="')[-1].split('">')[0]
    #             ast=rf.text.split('name="assignment_token" value="')[-1].split('">')[0]
    #             break

    #         else:
    #             head['referer']='https://twitter.com/account/access?lang=en'
    #             aut=rf.text.split('name="authenticity_token" value="')[-1].split('">')[0]
    #             ast=rf.text.split('name="assignment_token" value="')[-1].split('">')[0]

    #         #1054000311
    #         if False:
    #             pay=f"authenticity_token={aut}&assignment_token={ast}&lang=en&flow=&send=true&country_code=7&phone_number=9774036531&discoverable_by_mobile_phone=on&privacy_policy_initial_value="
    #             rf=s.post('https://twitter.com/account/access',data=pay,headers=head,timeout=10,proxies=proxy,cookies=cookies)
    #             print(rf.text)
    #             print(rf)

    #     pay={
    #         'authenticity_token': aut,
    #     'assignment_token': ast,
    #     'lang': 'en',
    #     'flow': '',
    #     'ui_metrics': metricsu
    #     }
    #     r=s.post('https://twitter.com/account/access?lang=en',data=pay,headers=head,timeout=10,proxies=proxy,cookies=cookies)
        
    #     print(r)
        
    #     r=s.get('https://twitter.com/?lang=en',headers=head,timeout=10,proxies=proxy,cookies=cookies)
    #     print(r)
    #     print(s.cookies.get_dict())


    def send_requests(acp_create,a1,a2,localsystemn,cucu):
        global changing_api_rn
        global sending_req_rn
        global ersin2
        global ersin

        print("VASEK ZAPUSKAI HAHAHAHA")
        
        
        ac=f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create'
        
        for hjk in range(a1,a2):
            try:
                fa=acp_create[hjk]
                tocont=True
            except:
                tocont=False



            if tocont:
                try:
                    ctsh=float(fa.split(':')[-1])
                except:
                    ctsh=1

                #if ctsh+28*60*60*24<time.time():
                if True:
                    tocont=True
                else:
                    tocont=False

                if tocont:
                    try:
                       
                        head,mm,cookies=system_check_start(fa)
                       
                            

                        #uid=random.choice(['1381699264011771906','1415078650039443456','859011517','5863182','94261044'])
                        with open('/root/work/farm_ids.txt','r') as fid:
                            fid=fid.readlines()
                        uid=random.choice(fid)
                        uid=uid.replace('\n','')
                        if False:
                            rf=follow(head,uid,cookies)
                        else:
                            rf=twit(head,cookies)

                        
                            #print('WARNING CHE ZA HUINA ERROR')
                        if rf==True:
                            dfv=False

                        elif rf==False:
                            dfv=True
                        else:
                            if 'Missing TwitterUserNotSuspended' in rf.text or 'temporarily locked' in rf.text or 'Your account is suspended' in rf.text:
                                dfv=True
                            else:
                                dfv=False

                        try:
                            if rf.status_code==200:
                                dfv=False
                        except:
                            pass

                        #if 'Missing TwitterUserNotSuspended' in rf.text or 'temporarily locked' in rf.text or 'Your account is suspended' in rf.text:
                        if dfv==True:

                            # try:
                            #     print(rf.text,'eto rf text')
                            # except:
                            #     print(r)

                            head["authorization"]='Bearer AAAAAAAAAAAAAAAAAAAAACHguwAAAAAAaSlT0G31NDEyg%2BSnBN5JuyKjMCU%3Dlhg0gv0nE7KKyiJNEAojQbn8Y3wJm1xidDK7VnKGBP4ByJwHPb' 

                            if rf.text!=r'{"errors":[{"code":64,"message":"Your account is suspended and is not permitted to access this feature."}]}' and rf.text!=r'{"errors":[{"code":326,"message":"To protect our users from spam and other malicious activity, this account is temporarily locked. Please log in to https://twitter.com to unlock your account.","sub_error_code":0,"bounce_location":"https://twitter.com/account/access"}]}':
                                try:
                                    print(rf,fa.split(":")[0])
                                    print(rf.text,fa.split(":")[0])
                                    print(rf.text,fa.split(":")[0])
                                except:
                                    print(f'NEOBICHNII 403 {fa.split(":")[0]}')
                                    if 'temporarily locked' in rf.text or 'Missing TwitterUserNotSuspended' in rf.text:
                                        print(True,fa.split(":")[0])
                                    else:
                                        print(False,fa.split(":")[0])
                            
                            if 'temporarily locked' in rf.text:
                                res='Bouncer Appeals' 
                            else:
                                res='Suspended'

                            if res=='Suspended' and False:
                                xfg=0
                                tex=gen_appeal_tex()
                                while ersin>=3:
                                    time.sleep(1)
                                if True:
                                    while True:
                                        token,titid=solvecaptcha('https://help.twitter.com/en/forms/account-access/appeals',fa.split(':')[4],'C07CAFBC-F76F-4DFD-ABFA-A6B78ADC1F29',[False,False,True,False],proxystr=proxystr)
                                        if token==None:
                                            #raise Exception('TOO LONG CAPTCHA2 ERROR')
                                            xfg+=1
                                        elif token!=False:
                                            if 'sup=1' not in token:
                                                token=token.replace('|at=40|rid=','|at=40|sup=1|rid=')
                                            if '|lang=' not in token:
                                                token=token.replace('|pk=','|lang=en|pk=')

                                            # gg=token.split('|r=')[-1].split('|met')[0]
                                            # token=token.replace(gg,'eu-west-1')
                                            break
                                        else:
                                            xfg+=1
                                        if xfg==3:
                                            print('dolgo')
                                            raise Exception('TOO LONG CAPTCHA1 ERROR')
                                            xfg=0
                                else:
                                    titid=0
                                    #token=get_token('3')
                                    #0152B4EB-D2DC-460A-89A1-629838B529C9
                                    #token=guru_token('B7D8911C-5CC8-A9A3-35B0-554ACEE604DA',proxystr,None,uak)
                                    #PAPAPAPAPAPA
                                
                                
                                
                                #{"stringEntries": {"_FormPath": "/content/help-twitter/en/forms/account-access/appeals/jcr:content/root/responsivegrid/ct16_columns_spa_cop/col2/f200_form","Subject":"Your account is suspended or locked","Source_Form__c":"locked_account","Type_of_Issue__c":"Not available","Category__c":"Bouncer Appeals","Referral_Source__c":"","Referral_Client__c":"","Screen_Name__c":"@barb_gerlach",               "Form_Email__c": "iq*****@ou*****.com", "DescriptionText": "unlock me. I am new.",                                                                           "arkoseVerificationToken": "6863cd1551e92988.1057380505 |r=eu-west-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|lang=en|pk=C07CAFBC-F76F-4DFD-ABFA-A6B78ADC1F29|at=40|sup=1|rid=63|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager"}}
                                #{'stringEntries': {'_FormPath': '/content/help-twitter/en/forms/account-access/appeals/jcr:content/root/responsivegrid/ct16_columns_spa_cop/col2/f200_form', 'Subject': 'Your account is suspended or locked', 'Source_Form__c': 'locked_account', 'Type_of_Issue__c': 'Not available', 'Category__c': 'Bouncer Appeals', 'Referral_Source__c': '', 'Referral_Client__c': '', 'Screen_Name__c': '@barb_gerlach', 'Form_Email__c': 'iq*****@ou*****.com', 'DescriptionText': 'hello there, how that happend? so unban that is most likely miss. plsplspls FIX THIS.. Thanks ', 'arkoseVerificationToken': '22863cd14da4e4b89.8093503505|r=eu-west-1|metabgclr=transparent|guitextcolor=%23000000|metaiconclr=%23555555|meta=3|meta_height=523|meta_width=558|lang=en|pk=C07CAFBC-F76F-4DFD-ABFA-A6B78ADC1F29|at=40|sup=1|rid=50|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager'}}
                                lnl=random.choice(['en','ru','fr','de','gr','id','it','tr','nl','ha','ko','pt','es','ar','bn','hi','ja'])
                                pay={"stringEntries":{f"_FormPath":f"/content/help-twitter/{lnl}/forms/account-access/appeals/jcr:content/root/responsivegrid/ct16_columns_spa_cop/col2/f200_form","Subject":"Your account is suspended or locked","Source_Form__c":"locked_account","Type_of_Issue__c":"Not available","Category__c":res,"Referral_Source__c":"","Referral_Client__c":"","Screen_Name__c":f"@{fa.split(':')[0]}","Form_Email__c":f"{fa.split(':')[2][0:2].lower()}*****@{fa.split(':')[2].split('@')[-1][0:2]}*****.{fa.split(':')[2].split('.')[-1]}","DescriptionText":tex,"arkoseVerificationToken":token}} 
                                #   {"stringEntries":{"_FormPath":"/content/help-twitter/ru/forms/account-access/appeals/jcr:content/root/responsivegrid/ct16_columns_spa_cop/col2/f200_form","Subject":"Your account is suspended or locked","Source_Form__c":"locked_account","Type_of_Issue__c":"Not available","Category__c":"Bouncer Appeals","Referral_Source__c":"","Referral_Client__c":"","Screen_Name__c":"@NftSol86","Form_Email__c":"zi*****@ho*****.com","DescriptionText":"wtf? I already sent it.","arkoseVerificationToken":"6721744acd04c0a92.6805585305|r=eu-west-1|meta=3|meta_width=558|meta_height=523|metabgclr=transparent|metaiconclr=%23555555|guitextcolor=%23000000|lang=ru|pk=C07CAFBC-F76F-4DFD-ABFA-A6B78ADC1F29|at=40|sup=1|rid=84|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com|smurl=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager"}}
                                
                                while True:
                                    try:
                                        while changing_api_rn:
                                            time.sleep(0.2)
                                        sending_req_rn=True
                                        r=requests.post('https://api.twitter.com/help-center/forms/api/prod/form_submission.json',headers=head,timeout=30,cookies=cookies,proxies=proxy,json=pay)
                                        if r.status_code!=200:
                                            if 'Unsupported account state'  in r.text:
                                                print(r.text)
                                                print('AKK VALID NO MI ZAPISHEM V REUQESTS BECAUSE WE ARE LAZU AF',fa.split(':')[0])
                                                validka=True
                                                #break
                                            else:
                                                print(r,fa.split(':')[0])
                                                try:
                                                    print(r.text,fa.split(':')[0])
                                                except:
                                                    pass
                                                print(pay,fa.split(':')[0])
                                                #break
                                            
                                            
                                        else:
                                            break
                                    except Exception as xxxc:
                                        sending_req_rn=False
                                        xfg+=1
                                        if xfg>1:
                                            
                                            ersin2+=1
                                            if ersin2>=2:
                                                
                                                ersin=3
                                                while sending_req_rn:
                                                    time.sleep(0.2)
                                                changing_api_rn=True
                                                while ersin>=3:
                                                    changecr()
                                                    time.sleep(1)
                                                ersin2=0
                                                changing_api_rn=False
                                            raise Exception(xxxc)

                                sending_req_rn=False
                                print('DONE REQUEST',fa.split(':')[0], proxy_id)

                                #ersin=0
                                
                                with lock:
                                    try:
                                        float(fa.split(':')[-1].replace('\n',''))
                                        acpnewi=fa.split(':')
                                        acpnewi[-1]=f"{str(time.time())}\n"
                                        acpnewi=':'.join(acpnewi)
                                    except Exception as x:
                                        print(repr(x))
                                        print(f'FLOAT ERROR {fa.split(":")[0]}')
                                        fca=fa.replace('\n','')
                                        acpnewi=f"{fca}:{time.time()}\n"
                                    
                                    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/requested.txt','a') as acpdn:    
                                        acpdn.write(acpnewi)

                                    with open(f'{ac}.txt','r') as acpch:       
                                        acp2=acpch.readlines()

                                    acptw=acp2
                                    while True:
                                        try:
                                            acptw.remove(fa)
                                        except:
                                            break
                                    
                                    with open(f'{ac}.txt','w') as acpch:        
                                        acpch.writelines(acptw)
                                        print(len(acptw))
                            
                            elif res=='Bouncer Appeals':
                                for zzzxxxx in range(3):
                                    try:
                                        cookies2,ver=unlock.unlock(cookies,
                                        #asocks[f"unlock_tw_{systemn}_{int(cucu)}"]
                                        proxystr
                                        ,fa.split(':')[0]
                                        ,head['User-Agent'])
                                        if ver==True:
                                            print(f"DONE UNLOCKED DONE WARNING {fa.split(':')[0]}")
                                            break
                                        else:
                                            cookies2=None
                                            raise Exception(ver)
                                    except Exception as zxcc:
                                        print(zxcc,fa.split(':')[0],
                                        #asocks[f"unlock_tw_{systemn}_{int(cucu)}"]
                                        proxystr
                                        )
                                        cookies2=None
                                        

                                if cookies2:
                                    try:
                                        cookies=':'.join(fa.split(':')[5:-2])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                        cookies=json.loads(cookies)
                                        fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)+':'+':'.join(fa.split(':')[-2:])

                                    except Exception as x:
                                            try:
                                                cookies=':'.join(fa.split(':')[5:-2]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                                cookies=json.loads(cookies)
                                                fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)+':'+':'.join(fa.split(':')[-2:])
                                            except Exception as x:
                                                try:
                                                    cookies=':'.join(fa.split(':')[5:-1])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                                    cookies=json.loads(cookies)
                                                    fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)+':'+':'.join(fa.split(':')[-1:])
                                                except Exception as x:
                                                    try:
                                                        cookies=':'.join(fa.split(':')[5:-1]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                                        cookies=json.loads(cookies)
                                                        fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)+':'+':'.join(fa.split(':')[-1:])
                                                    except Exception as x:
                                                        try:
                                                            cookies=':'.join(fa.split(':')[5:]).replace('\n','')#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                                            cookies=json.loads(cookies)
                                                            fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)
                                                        except Exception as x:
                                                            try:
                                                                cookies=':'.join(fa.split(':')[5:]).replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false').replace('\n','')
                                                                cookies=json.loads(cookies)
                                                                fa2=':'.join(fa.split(':')[:5])+':'+json.dumps(cookies2)
                                                            except Exception as x:
                                                                try:
                                                                    cookies=':'.join(fa.split(':')[6:-2])#.replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false').replace('\n','')
                                                                    cookies=json.loads(cookies)
                                                                    head['User-Agent']=fa.split(':')[5]
                                                                    fa2=':'.join(fa.split(':')[:6])+':'+json.dumps(cookies2)+':'+':'.join(fa.split(':')[-2:])
                                                                    
                                                                except Exception as x:
                                                                    print(repr(x))
                                                                    print(':'.join(fa.split(':')[5:-2]))
                                                                    raise Exception(f"ERROR COOKIES FORMAT {fa.split(':')[0]}") 


                                    try:
                                        float(fa2.split(':')[-1].replace('\n',''))
                                        accc=fa2.split(':')
                                        accc[-1]=f"{str(time.time())}\n"
                                        fa2=':'.join(accc)
                                    except Exception as x:
                                        print(repr(x))
                                        print(f'FLOAT ERROR {fa2.split(":")[0]}')
                                        fa2=fa2

                                    with lock:
                                        with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','a') as acpdn:    
                                            acpdn.write(fa2)

                                    
                                        with open(f'{ac}.txt','r') as acpch:       
                                            acp2=acpch.readlines()

                                        acptw=acp2
                                        while True:
                                            try:
                                                acptw.remove(fa)
                                            except:
                                                break
                                        
                                        with open(f'{ac}.txt','w') as acpch:        
                                            acpch.writelines(acptw)
                                            print(len(acptw))


                        else:
                            print('DONE F',fa.split(":")[0])
                        
                            try:
                                float(fa.split(':')[-1].replace('\n',''))
                                accc=fa.split(':')
                                accc[-1]=f"{str(time.time())}\n"
                                acpnewi=':'.join(accc)
                            except Exception as x:
                                print(repr(x))
                                print(f'FLOAT ERROR {fa.split(":")[0]}')
                                acpnewi=fa

                            MAIL=fa.split(':')[2]
                            MPASS=fa.split(':')[3]
                            mm.delete(MAIL,MPASS)
                            global aki2
                            aki2.append([MAIL,MPASS])


                            with lock:
                                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','a') as acpdn:    
                                    acpdn.write(acpnewi)

                            
                                with open(f'{ac}.txt','r') as acpch:       
                                    acp2=acpch.readlines()

                                acptw=acp2
                                while True:
                                    try:
                                        acptw.remove(fa)
                                    except:
                                        break
                                
                                with open(f'{ac}.txt','w') as acpch:        
                                    acpch.writelines(acptw)
                                    print(len(acptw))

                    except Exception as x:
                        print(repr(x),'sending req')

                        if str(x)=='mail ban':
                            if False:
                                while True:
                                    try:
                                        w_repl.remove(fa)
                                    except:
                                        break
                                while True:
                                    try:
                                        w_req.remove(fa)
                                    except:
                                        break
                            else:
                                with lock:
                                    with open(f'{ac}.txt','r') as acpch:       
                                        acp2=acpch.readlines()

                                    acptw=acp2
                                    acptw.remove(fa)
                                    
                                    with open(f'{ac}.txt','w') as acpch:        
                                        acpch.writelines(acptw)
                                        print(len(acptw))

                                    with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/mailban.txt','a') as mmbn:
                                        mmbn.writelines([fa]) 
                        print(ersin)
                
        global alld
        try:
            alld[cucu]=True
        except:
            print('PIZDEC KAKOYTA ERRROR SENDING REQ CUCU ALLD HuITA')

        while False in alld:
            time.sleep(1)


        if cucu==0:
            print("FINISHED HAHA")
            with lock:
                
                ####
                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','r') as acp_create2:
                    acp_create2=acp_create2.readlines()

                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','a') as acp_create:
                    acp_create.writelines(acp_create2) 

                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','w') as acp_create2:
                    acp_create2.writelines(['']) 
                ####


                ####
                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','r') as acp_create2:
                    acp_create2=acp_create2.readlines()

                with open(f'create_and_unban_SYSTEM/{systemn}/not403.txt','a') as acp_create:
                    acp_create.writelines(acp_create2) 

                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','w') as acp_create2:
                    acp_create2.writelines(['']) 
                ####


                ####
                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/requested.txt','r') as acp_create2:
                    acp_create2=acp_create2.readlines()

                with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','a') as acp_create:
                    acp_create.writelines(acp_create2) 

                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/requested.txt','w') as acp_create2:
                    acp_create2.writelines(['']) 
                ####


                ###
                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/mailban.txt','r') as mailbana2:
                    mailbana2=mailbana2.readlines()

                with open(f'create_and_unban_SYSTEM/{systemn}/mailban.txt','a') as mailbana:
                    mailbana.writelines(mailbana2) 

                with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/mailban.txt','w') as mailbana:
                    mailbana.writelines(['']) 
                ###

            print("WARNING STRARTING OPACHKI")
            mka=mmail.dop_deiv()    
            erkas=mka.delete_rec(aki2)
            print("WARNING DONE OPACHCKI")
            
            global slowed
            while True:
                if slowed<=-100:
                    #time.sleep(60)
                    break
                else:
                    time.sleep(1)

            global global_dop_system
            gds=[localsystemn]
            gds.extend(global_dop_system)
            global_dop_system=gds
            print(gds)
                
    
    def add_phone(acp_create,localsystemn):
        print("WARNNG VASEK ZAPUSKAI PHONCHICK HAHAHAHAHAHAHAAAhaahahahahahaaaa....h.. .")
        aki3=[]
        global cur_dr
        ersinph=0
        a_mailban=[]
        
        ac=f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/to_phone'
        ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',None)
        phone,id=ph.get_phone(cr)
        for fa in acp_create:
            tocont=True

            if tocont:
                try:
                    dn=False
                    try:
                        #head,mm,cookies=system_check_start(fa,False)
                        head,cookies=system_check_start(fa,False)
                    except:
                        print(fa)
                    #uid=random.choice(['1381699264011771906','1415078650039443456','859011517','5863182','94261044'])
                    with open('/root/work/farm_ids.txt','r') as fid:
                        fid=fid.readlines()
                    uid=random.choice(fid)
                    uid=uid.replace('\n','')
                    rf=follow(head,uid,cookies)
                    if 'Missing TwitterUserNotSuspended' in rf.text or 'temporarily locked' in rf.text  or 'Your account is suspended' in rf.text:
                        
                        if 'temporarily locked' in rf.text:
                            res='Bouncer Appeals' 
                        else:
                            res='Suspended'
                        
                        if res=='Bouncer Appeals':
                            try:
                                dn=False
                                cur_dr=True
                                dr=selenium_driver_gen.sel_driver_gen()
                                driver,proxdict,ua =dr.gen('phone',proxystr)
                                print(driver.session_id)
                                driver.set_page_load_timeout(80)
                                driver.set_window_size(random.randint(1549,1700), 1000)

                                if ':{' in fa:
                                #if type(cookies)==dict:
                                    cock=f"{{{':'.join(fa.split(':{')[-1].split(':')[:-2])}".replace('"','\\"').replace("'",'"').replace('True','true').replace('False','false')
                                    #print(cock)
                                    cock=json.loads(cock)
                                    new_cock=[]
                                    for name in cock:
                                        if name=='_ga':
                                            sex=False
                                        else:
                                            sex=True
                                        if name=='ct0':
                                            ss='Lax'
                                        else:
                                            ss='None'
                                        if name=='kdt' or name=='auth_token' or name=='_twitter_sess':
                                            ht=True
                                        else:
                                            ht=False
                                        new_cock.append({'domain':'.twitter.com', 'expiry': int(str(time.time()).split('.')[0])+700*24*60*60, 'httpOnly': ht, 'name': name, 'path': '/', 'sameSite': ss, 'secure': sex, 'value': cock[name]})
                                    # ckc=''
                                    # for c in new_cock:
                                    #     ckc+=f"{json.dumps(c)}, "
                                    # new_cock=f"[{ckc[:-2]}]"
                                    # new_cock=new_cock.replace("'",'"').replace('True','true').replace('False','false').replace('None','null').replace('"null"','"None"')
                                    cookies=new_cock

                                if True:
                                    driver.get('https://twitter.com/')
                                    for cookie in cookies:
                                        try:
                                            driver.add_cookie(cookie)
                                        except Exception as x:
                                            print(cookie)
                                            raise Exception(x)
                                    driver.get(f'https://twitter.com/{fa.split(":")[0]}')


                                if True:               
                                    limt=3
                                    tries=1
                                    while True:
                                        try:
                                            el=WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Start"]')))
                                            #time.sleep(1)
                                            el.click()
                                        except TimeoutException:
                                            pass

                                        try:
                                            try:
                                                WebDriverWait(driver, 5).until(EC.frame_to_be_available_and_switch_to_it((By.ID,'arkose_iframe')))
                                                cp=True
                                            except TimeoutException:
                                                print('no captcha')
                                                cp=False

                                            if cp:
                                                print('captcha')
                                                driver.switch_to.default_content()
                                                x=0
                                                xfg=0
                                                while True:
                                                    try: 
                                                        while True:
                                                            token,titid=solvecaptcha(driver.current_url,ua,'0152B4EB-D2DC-460A-89A1-629838B529C9',[False,False,True,True],proxystr=proxystr)
                                                            #print(token)
                                                            if token==None:
                                                                #raise Exception('TOO LONG CAPTCHA2 ERROR')
                                                                xfg+=1
                                                                pass
                                                            elif token!=False:
                                                                break
                                                            else:
                                                                xfg+=1

                                                            if xfg>10:
                                                                print('dolgo')
                                                                raise Exception('TOO LONG CAPTCHA1 ERROR')
                                                        
                                                        if token==False:
                                                            raise TimeoutException('NO SOLVING CAPTCHA')    
                                                        else:    
                                                            token=token.replace('|pk=','|lang=en|pk=')  
                                                            print('solved')
                                                            try:
                                                                #input('?> - ')
                                                                driver.execute_script(f'''var anyCaptchaToken = '{token}';
                                                                var enc = document.getElementById('arkose_iframe');
                                                                var encWin = enc.contentWindow || enc;
                                                                var encDoc = enc.contentDocument || encWin.document;
                                                                let script = encDoc.createElement('SCRIPT');
                                                                script.append('function AnyCaptchaSubmit(token) {{ parent.postMessage(JSON.stringify({{ eventId: "challenge-complete", payload: {{ sessionToken: token }} }}), "*") }}');
                                                                encDoc.documentElement.appendChild(script);
                                                                encWin.AnyCaptchaSubmit(anyCaptchaToken);''')  
                                                            except Exception as x:
                                                                print(repr(x))
                                                            l=WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.XPATH,'//*[@class="PageHeader Edge"]'))).text
                                                            break
                                                    except TimeoutException:
                                                        x+=1
                                                        if x==3:
                                                            raise Exception('NO SOLVING CAPTCHA')
                                                        driver.get(driver.current_url)

                                            
                                                
                                            
                                            try:
                                                l=WebDriverWait(driver, 8).until(EC.presence_of_element_located((By.XPATH,'//*[@class="PageHeader Edge"]'))).text
                                            except TimeoutException:
                                                raise Exception('TOO LONG LOADING AFTER CAPTHCA ACCESS PAGE')

                                            print(l.strip())

                                            cont=False
                                            if l.strip()=='Enter the confirmation code':
                                                driver.get('https://twitter.com/account/access?lang=en&did_not_receive=true')
                                                cont=True
                                                l=WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.XPATH,'//*[@class="PageHeader Edge"]'))).text  
                                            
                                            elif l.strip()=='Enter your phone number' or l.strip()=='Verify your phone number':
                                                cont=True


                                            if cont:
                                                # if l.strip()=='Your account has been locked.' :
                                                #     el=WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Start"]')))
                                                
                                                #     el.click()
                                                if l.strip()=='Enter your phone number' :

                                                    # ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',None)
                                                    # phone,id=ph.get_phone(cr)
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID,'country_code'))).click()
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="country_code"]/option[1]'))).click()
                                                        #//*[@id="country_code"]/option[1]
                                                        #//*[@id="country_code"]/option[107]
                                                    
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID,'phone_number'))).send_keys(phone.replace('+380','').replace('+7',''))  

                                                    try:     
                                                        WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Next"]'))).click()
                                                    except:
                                                        WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Send code"]'))).click()
                                                    
                                                    while True:

                                                        try:
                                                            l=WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.XPATH,'//*[@class="PageHeader Edge"]'))).text
                                                            if l.strip()=='Something went wrong.':
                                                                #WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@href="/account/access?lang=en"]')))
                                                                dn='try_later'
                                                                ersinph-=1
                                                                raise Exception('ERROR try later') 
                                                        except TimeoutException:
                                                            pass


                                                        try:
                                                            WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.ID,'code')))
                                                            break
                                                        except:
                                                            ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',None)
                                                            phone,id=ph.get_phone(cr)
                                                            #input('?')
                                                            WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID,'phone_number'))).send_keys(phone.replace('+380','').replace('+7',''))   
                                                            #time.sleep(2)      
                                                            try:     
                                                                WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Next"]'))).click()
                                                            except:
                                                                WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Send code"]'))).click()
                                                    

                                                    code=ph.get_code(id,12)

                                                        
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID,'code'))).send_keys(code)
                                                    #time.sleep(2)
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Next"]'))).click()
                                                    dn='phone'

                                                    el=WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Continue to Twitter"]')))
                                                    #time.sleep(2)
                                                    el.click()


                                                elif l.strip()=='Verify your phone number' :
                                                    if tries==1:
                                                        ersinph-=1
                                                        dn='already'
                                                        #print('ERROR ALREADY HAS PHONE')
                                                        raise Exception('ERROR ALREADY HAS PHONE')

                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Send code"]'))).click()


                                                    WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID,'code')))

                                                    try:
                                                        code=ph.get_code(id,12)
                                                    except:
                                                        raise Exception('no code2')

                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID,'code'))).send_keys(code)
                                                    #time.sleep(2)
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Next"]'))).click()
                                                    dn='phone'

                                                    el=WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Continue to Twitter"]')))
                                                    #time.sleep(2)
                                                    el.click()

                                            

                                            elif l.strip()=='Something went wrong.':
                                                #WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@href="/account/access?lang=en"]')))
                                                dn='try_later'
                                                ersinph-=1
                                                raise Exception('ERROR try later')          

                                            else:
                                                el=WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Continue to Twitter"]')))
                                                #time.sleep(1)
                                                el.click()
                                                #time.sleep(2)
                                                dn='unban'

                                            try:
                                                dopdop=False
                                                for suka in range(7):
                                                    try:
                                                        WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@href="/explore"]')))
                                                        dopdop=True
                                                        break
                                                    except:
                                                        pass
                                                    try:
                                                        WebDriverWait(driver, 1).until(EC.element_to_be_clickable((By.XPATH,'//*[@value="Start"]')))
                                                        dopdop=False
                                                        break
                                                    except:
                                                        pass



                                                if dopdop:
                                                    print('unlocked')
                                                    break
                                            except TimeoutException:
                                                raise Exception('NEED NEW TRY')

                                        except Exception as xxx:
                                            
                                            

                                            if dn=='already':
                                                raise Exception(xxx)
                                            elif dn=='try_later':
                                                raise Exception(xxx)
                                            else:
                                                print(repr(xxx))
                                                
                                            if str(xxx)=='no code':
                                                phone,id=ph.get_phone(cr)

                                            if str(xxx)=='NEED NEW TRY':
                                                limt+=1
                                            if tries>=limt:
                                                dn=False
                                                if str(xxx)=='no code' or str(xxx)=='no code2' :
                                                    phone,id=ph.get_phone(cr)
                                                print('unlock err',end=' ')
                                                

                                                raise Exception(xxx)

                                            
                                            tries+=1
                                            print('new try')
                                            #driver.get(driver.current_url)
                                            dn=False
                                


                                #if l.strip()=='Enter your phone number' or l.strip()=='Verify your phone number' :
                                if False:
                                    try:
                                        noersph='None'
                                        driver.get('https://twitter.com/i/flow/two-factor-sms-enrollment')
                                        tries=0
                                        
                                        if tries==0:
                                            x1=4
                                        else:
                                            x1=10
                                            
                                            ###PASSWORD
                                        try:
                                            WebDriverWait(driver, x1).until(EC.element_to_be_clickable((By.XPATH,'//*[@type="password"]'))).send_keys(fa.split(':')[1])
                                            time.sleep(1)
                                            #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div/div#new
                                            #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div#old
                                            WebDriverWait(driver, 15).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div/div'))).click()
                                        except TimeoutException:
                                            raise Exception('blocked')
                                            ###PASSWORD\

                                        WebDriverWait(driver, 15).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div'))).click()

                                    
                                        #time.sleep(0.5)
                                        while noersph=='None' and tries<3:
                                            tries+=1

                                            

                                            if False:
                                                el=WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="phone_number"]')))
                                                ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',proxy)
                                                try:
                                                    phone,idp=ph.get_phone(cr)
                                                except Exception as x:  
                                                    try:
                                                        phone,idp=ph.get_phone(cr)
                                                    except:
                                                        print('no money or pgones ph')
                                                        raise TimeoutException

                                            else:
                                                time.sleep(1)
                                                WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div/div/div/div/div/div[2]/div[2]/div'))).click()
                                                
                                                
                                            #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div#new
                                            #//*[@id="react-root"]/div/div/div[2]/main/div/div/div/section[2]/div[2]/div[2]/div/div/label/div/div[2]#old
                                            

                                            #WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div'))).click()#old
                                            
                                            if False:
                                                xxx=0
                                                while True:
                                                    xxx+=1
                                                    el=WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="phone_number"]')))
                                                    el.clear()
                                                    el.send_keys(phone)
                                                    time.sleep(3.5)
                                                    #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div#new
                                                    #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div#old
                                                    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div/div'))).click()
                                                    # try:
                                                    #     time.sleep(1)
                                                    #     driver.find_element_by_xpath('//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div').click()
                                                    # except:
                                                    #     pass
                                                    # time.sleep(1)
                                                    # WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[3]/div/div/div/div/div/div[2]/div[2]/div[2]/div[1]'))).click()
                                                    
                                                    nxtst=False
                                                    time.sleep(2.5)
                                                    try:
                                                        ep=WebDriverWait(driver, 2).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="verfication_code"]')))
                                                        nxtst=True
                                                        break
                                                    except TimeoutException:
                                                        print('222')
                                                        #noersph=None
                                                        if xxx==4 and nxtst==False:
                                                            noersph=None
                                                            raise Exception('limit or no num err')

                                                        try:
                                                            ph=phonie.phonevervip('c9d756ce5d2e1b709a1d53230abe9196bb3f0c68','tw','smsi.vip',None)
                                                            phone,idp=ph.get_phone(cr)
                                                        except Exception as x: 
                                                            try:
                                                                phone,idp=ph.get_phone(cr)
                                                            except:
                                                                noersph=None
                                                                raise Exception('no money or pgones ph')
                                                        
                                                codep=None
                                                #WebDriverWait(driver, 2).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[1]/div/div/div/div/div[1]/div'))).click()
                                                if nxtst:
                                                    try:
                                                        codep=ph.get_code(idp,8)
                                                    except:

                                                        if tries==4:
                                                            noersph=None
                                                            raise Exception('no code xd')

                                                        # try:
                                                        #     phone,idp=self.ph.get_phone(self.cr)
                                                        # except:
                                                        #     noersph=None
                                                        #     raise Exception('no money or pgones ph')


                                                        
                                                    #     try:
                                                    #         WebDriverWait(driver, 4).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[1]/div/div[2]/div/div/div/div/span/span'))).click()
                                                    #         time.sleep(0.5)
                                                    #         WebDriverWait(driver, 4).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[3]/div/div/div/div[2]/div[3]/div/div/div/div[2]'))).click()
                                                    #         try:
                                                    #             codep=self.ph.get_code(idp,10)
                                                    #         except:
                                                    #             print('code err')

                                                    #     except StaleElementReferenceException:
                                                    #         print('code err')
                                                    
                                                    if codep:
                                                        WebDriverWait(driver, 4).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="verfication_code"]'))).send_keys(codep)
                                                        break

                                                    # if tries==2:
                                                    #     try:
                                                    #         phone,idp=self.ph.get_phone(self.cr)
                                                    #     except:
                                                    #         print('no money or pgones ph')
                                                    #         raise TimeoutException
                                                            
                                                    if tries==4:
                                                        noersph=None
                                                        
                                                        raise Exception('no code xd')
                                                    WebDriverWait(driver, 2).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[1]/div/div/div/div/div[1]/div'))).click()
                                        
                                        else:
                                            time.sleep(3)
                                            WebDriverWait(driver, 2).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="verfication_code"]')))
                                            codep=ph.get_code(id,15)
                                            WebDriverWait(driver, 4).until(EC.element_to_be_clickable((By.XPATH,'//*[@name="verfication_code"]'))).send_keys(codep)
                                            WebDriverWait(driver, 2).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[1]/div/div/div/div/div[1]/div'))).click()
                                        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div'))).click()
                                        try:
                                            time.sleep(2)
                                            driver.find_element_by_xpath('//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div[2]/div/div/div').click()
                                        except:
                                            pass
                                        #//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div/div/div/div/div/div[2]/div[1]/div[2]/span/span/span/text()

                                        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="layers"]/div[2]/div/div/div/div/div/div[2]/div[2]/div/div/div[2]/div[2]/div/div/div/div/div/div[2]/div[2]/div[2]'))).click()
                                        recode=WebDriverWait(driver, 15).until(EC.element_to_be_clickable((By.XPATH,'//*[@id="react-root"]/div/div/div[2]/main/div/div/div/section[2]/div[2]/div[3]/div/span'))).text.replace(' ','')
                                        #time.sleep(2)
                                        noersph=True
                                        dn='unban_phone_2fa'

                                    except Exception as x:
                                            print(repr(x))
                                            if dn==False:
                                                noersph=False
                                                
                                            raise Exception('phone 2 err')

                                    


                                cookies = driver.get_cookies()
                                cc=[]
                                for cookie in cookies:
                                        cc.append(f"{cookie['name']}={cookie['value']}")

                                cc='; '.join(cc)

                                print('DONE',fa.split(':')[0])
                                
                                ersinph=0


                            except Exception as x:
                                print(repr(x))
                                ersinph+=1

                            finally:
                                cur_dr=False
                                try:
                                    driver.quit()
                                except:
                                    pass
                                try:
                                    os.remove('phone.zip')
                                except:
                                    pass

                                if dn!=False:
                                    
                                    try:
                                        float(fa.split(':')[-1].replace('\n',''))
                                        acpnewi=fa.split(':')
                                        acpnewi[-1]=f"{str(time.time())}\n"
                                        acpnewi=':'.join(acpnewi)
                                    except Exception as x:
                                        print(repr(x))
                                        print(f'FLOAT ERROR {fa.split(":")[0]}')
                                        fca=fa.replace('\n','')
                                        acpnewi=f"{fca}:{time.time()}\n"
                                    
                                    if True:
                                        with lock:
                                    
                                    
                                            with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/phone.txt','a') as acpdn:    
                                                if dn=='phone':
                                                    rsd=fa.split(':')
                                                    lala=''
                                                    try:
                                                        int(rsd[-2])
                                                        lala=f"{lala}:{rsd[-2]}"
                                                    except:
                                                        pass
                                                    try:
                                                        float(rsd[-1])
                                                        llala=f"{lala}:{rsd[-1]}"
                                                    except:
                                                        pass
                                                    rsd=f'{":".join(rsd[0:4])}:{phone}:{":".join(rsd[4])}:{cc}{lala}'
                                                    acpdn.write(rsd)

                                                elif dn=='not403':
                                                    acpdn.write(acpnewi)

                                                else:
                                                    acpdn.write(fa)



                                                



                                    else:
                                        with open(f'unban_{dn}.txt','a') as acpdn:
                                            if dn=='phone':
                                                rsd=fa.split(':')
                                                rsd=f'{":".join(rsd[0:4])}:{phone}:{":".join(rsd[4:])}'
                                                acpdn.write(rsd)

                                            elif dn=='not403':
                                                acpdn.write(acpnewi)

                                            else:
                                                acpdn.write(fa)

                                        acptw=acp2
                                        acptw.remove(fa)
                                        
                                        with open(f'to_unban{unb1}.txt','w') as acpch:        
                                            acpch.writelines(acptw)
                                            print(len(acptw))


                                # if dn!='mail_ban':
                                #     changecr(ersin)
                                
                                if ersinph>=3:
                                    global ersin
                                    global changing_api_rn
                                    ersin=3
                                    while sending_req_rn:
                                        time.sleep(0.2)
                                    changing_api_rn=True
                                    while ersin>=3:
                                        
                                        try:
                                            changecr()
                                        except Exception as xzxc:
                                            print(repr(xzxc),'phone changecr')
                                            time.sleep(10)
                                        time.sleep(1)

                                    ersinph=0
                                    changing_api_rn=False
                                else:
                                    changecr()    
                                
                                if dn=='KeyboardInterrupt':
                                    raise Exception('stopped')
                            
                        else:
                            print(res,fa.split(':')[0])
                            with lock:
                                tocrackwrite=[fa]

                                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acpdnr:    
                                    acpdnr=acpdnr.readlines()

                                tocrackwrite.extend(acpdnr)

                                with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','w') as acpdn:    
                                    acpdn.writelines(tocrackwrite)
                    else:
                        print('DONE F',fa.split(":")[0])
                    
                        try:
                            float(fa.split(':')[-1].replace('\n',''))
                            accc=fa.split(':')
                            accc[-1]=f"{str(time.time())}\n"
                            acpnewi=':'.join(accc)
                        except Exception as x:
                            print(repr(x))
                            print(f'FLOAT ERROR {fa.split(":")[0]}')
                            acpnewi=fa

                        MAIL=fa.split(':')[2]
                        MPASS=fa.split(':')[3]
                        #mm.delete(MAIL,MPASS)
                        aki3.append([MAIL,MPASS])


                        with lock:
                            with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/not403.txt','a') as acpdn:    
                                acpdn.write(acpnewi)

                        
                            with open(f'{ac}.txt','r') as acpch:       
                                acp2=acpch.readlines()

                            acptw=acp2
                            while True:
                                try:
                                    acptw.remove(fa)
                                except:
                                    break
                            
                            with open(f'{ac}.txt','w') as acpch:        
                                acpch.writelines(acptw)
                                print(len(acptw))

                except Exception as xxxx:
                    print(repr(xxxx),'adding phone')

                    if str(xxxx)=='mail ban':
                        if False:
                            while True:
                                try:
                                    w_repl.remove(fa)
                                except:
                                    break
                            while True:
                                try:
                                    w_req.remove(fa)
                                except:
                                    break
                        else:
                            with lock:
                                with open(f'{ac}.txt','r') as acpch:       
                                    acp2=acpch.readlines()

                                acptw=acp2
                                acptw.remove(fa)
                                
                                with open(f'{ac}.txt','w') as acpch:        
                                    acpch.writelines(acptw)
                                    print(len(acptw))

                        a_mailban.append(fa)
                    print(ersin)
                    
                finally:
                    with lock:
                        with open(f'{ac}.txt','r') as acpch:       
                            acp2=acpch.readlines()

                        acptw=acp2
                        while True:
                            try:
                                acptw.remove(fa)
                            except:
                                break
                        
                        with open(f'{ac}.txt','w') as acpch:        
                            acpch.writelines(acptw)
                            print(len(acptw),'phones left')
                    

        print("NUNUNU")
        mka=mmail.dop_deiv()    
        erkas=mka.delete_rec(aki3)
        print("TOTAL OPA")



    if True:
        with open(f'create_and_unban_SYSTEM/{systemn}/{localsystemn}/create.txt','r') as acp_create2:
            acp_create2=acp_create2.readlines()

        
        print(len(acp_create2),'vsego')
                
        ggg=odnovrem_t*2
        ggg=10
        alld=[]
        aki2=[]
        ccc=len(acp_create2)//(ggg)+1
        
        for cjh in range(0,ggg):
            print(ccc*cjh,(ccc*(cjh+1)))
            alld.append(False)
            
            threading.Thread(target=send_requests, args=(acp_create2[:],ccc*cjh,ccc*(cjh+1),localsystemn,cjh,)).start()








    if True:
        ###  
        for acpshn in range(2):
            with open(f'create_and_unban_SYSTEM/{systemn}/create.txt','r') as acp_create:
                acp_create=acp_create.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/requested.txt','r') as acp_requested:
                acp_requested=acp_requested.readlines()

            with open(f'create_and_unban_SYSTEM/{systemn}/replied.txt','r') as acp_replied:
                acp_replied=acp_replied.readlines()



            acpsh=[acp_replied[:],acp_requested[:]][acpshn]
            ac=[f'create_and_unban_SYSTEM/{systemn}/replied',f'create_and_unban_SYSTEM/{systemn}/requested'][acpshn]

            print(ac)


            w_create=acp_create[:]
            w_req=acp_requested[:]
            w_repl=acp_replied[:]


            slowed+=len(acpsh)
            if True:
                for cjh in range(0,len(acpsh)):
                    tt=threading.Thread(target=check_mail, args=(cjh,cjh+1,acpsh,ac,0,))
                    tt.start()

        #input(f'{dodo} {ac} ?')


   


#rddyzz twitter id = 1455854481959268352
