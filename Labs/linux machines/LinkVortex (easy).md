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