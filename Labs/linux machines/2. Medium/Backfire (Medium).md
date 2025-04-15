# User flag
## 1. rustscan

```python
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJuxaL9aCVxiQGLRxQPezW3dkgouskvb/BcBJR16VYjHElq7F8C2ByzUTNr0OMeiwft8X5vJaD9GBqoEul4D1QE=
|   256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2oT7Hn4aUiSdg4vO9rJIbVSVKcOVKozd838ZStpwj8
443/tcp  open  ssl/http syn-ack ttl 63 nginx 1.22.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.22.1
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
| ssl-cert: Subject: commonName=127.0.0.1/stateOrProvinceName=Illinois/countryName=US/streetAddress=/postalCode=5487/localityName=Chicago
| Subject Alternative Name: IP Address:127.0.0.1
| Issuer: commonName=127.0.0.1/stateOrProvinceName=Illinois/countryName=US/streetAddress=/postalCode=5487/localityName=Chicago
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-15T07:38:08
| Not valid after:  2028-03-14T07:38:08
| MD5:   40f8:1e1c:70d0:b713:9578:f2fd:5f52:013a
| SHA-1: 1b99:5950:bf14:b8df:6740:05c1:74f1:9732:9fc5:ee37
| -----BEGIN CERTIFICATE-----
| MIIDvDCCAqSgAwIBAgIQLTeSLKepMhiu9KHG+6tfnTANBgkqhkiG9w0BAQsFADBg
| MQswCQYDVQQGEwJVUzERMA8GA1UECBMISWxsaW5vaXMxEDAOBgNVBAcTB0NoaWNh
| Z28xCTAHBgNVBAkTADENMAsGA1UEERMENTQ4NzESMBAGA1UEAxMJMTI3LjAuMC4x
| MB4XDTI1MDMxNTA3MzgwOFoXDTI4MDMxNDA3MzgwOFowYDELMAkGA1UEBhMCVVMx
| ETAPBgNVBAgTCElsbGlub2lzMRAwDgYDVQQHEwdDaGljYWdvMQkwBwYDVQQJEwAx
| DTALBgNVBBETBDU0ODcxEjAQBgNVBAMTCTEyNy4wLjAuMTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBALoNJuKr1aw91FsCES/qqzK6gbmosMPV7Ne5gKnP
| o/QFcBqdaoo3p1Al8bni0tfhdJZDGI9/M2fLs1jpEpAAAi9n0FyqVTaEd59lBH5b
| pQER8LzMryVdQ6lYQ/IAiCePSk8BJtDS7mdQmXV5PvrrEifZjgX1LhZJOomGQYLK
| 0RQ7E5Ex3huZeBQiTk4WM6C51LDoFyyWdn10lDx6VA4LmtqLy8ncSASYaicRAqdg
| uf8+BDGKgfCmGeRtz+fQ4UxycIcXCvj+9Qlg5XcVzhVrntPgbIqAgKogBN6lBWeT
| BN2Bem2M6JXo+eXnd9PH2CQuZTWT2eNoR3ijw4zjMxrXat0CAwEAAaNyMHAwDgYD
| VR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNV
| HRMBAf8EBTADAQH/MB0GA1UdDgQWBBSo7xm9gohEYfQAEQvjBWaibx4KvzAPBgNV
| HREECDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQBjHl4vttopM+QvxqbqAJp/
| 9R3eXwWnx5CYlvbCDCAbNpCRXmLAwBrE9PFR7ynCqdz/+7ydZvOkEc1kHCWU+SGX
| WSXUyGv9etuGWnbdkNYjG8DBz0/cgV5TxIoZLYaq/AMh0eZAIkAvcmfWbU0v5Ago
| +f/FHNEjFAZrFBL6Q46FtgdjZSOsg4jDTHPLpHTqI1fPbsXK8vTL0pj/SmY+vfO/
| eatGscpq+M//qtdZX7U9d2pA6r6rHSp+OSB36P8wsM/rFOYdznNJMRXnXzI03RWl
| rQW3an2T5/sbUpLSjFE7ZoCY/JLJgMmw9nUmCB0NBmR4LzaV1jqFgO/3OAGiGp9n
|_-----END CERTIFICATE-----
|_http-title: 404 Not Found

8000/tcp open  http     syn-ack ttl 63 nginx 1.22.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Index of /
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 12:31  disable_tls.patch
| 875   17-Dec-2024 12:34  havoc.yaotl
|_
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. get two files
```python
#  disable_tls.patch
┌──(kali㉿kali)-[~/Downloads]
└─$ cat disable_tls.patch 
Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
                }
 
                // start the teamserver
-               if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+               if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
                        logger.Error("Failed to start websocket: " + err.Error())
                }


# havoc.yaotl 
┌──(kali㉿kali)-[~/Downloads]
└─$ cat havoc.yaotl      
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
```
## 3. dirsearch
```
# nothing found
```

## 4. search for CVE
[CVE-2024-41570: Havoc-C2-SSRF-poc](https://github.com/chebuya/Havoc-C2-SSRF-poc/tree/main)
[Vulnerabilities in Open Source C2 Frameworks](https://blog.includesecurity.com/2024/09/vulnerabilities-in-open-source-c2-frameworks/)
=> combine: https://github.com/sebr-dev/Havoc-C2-SSRF-to-RCE

# root flag
