# Broken Link Injection

Some websites check broken links to find broken link-hijacking vulnerabilities

1- [https://ahrefs.com/broken-link-checker](https://ahrefs.com/broken-link-checker)

2- [deadlinkchecker.com](http://deadlinkchecker.com/)

3- [brokenlinkcheck.com](http://brokenlinkcheck.com/)

#### Steps <a href="#steps" id="steps"></a>

1. Manually find and click external links on the target site ( For Example:- Some Links to Social Media Accounts or Some external Media Link)
2.  While Doing Manual work also put [broken-link-checker](https://github.com/stevenvachon/broken-link-checker) in background using below Command interminal.

    `blc -rof --filter-level 3 https://example.com/`

    Ouput will be like Something.

    `─BROKEN─ https://www.linkedin.com/company/ACME-inc-/ (HTTP_999)`
3. Now you need to check if company has the page or not , if no then register as the company or try to get that username or url.

#### Alternate Step <a href="#alternate-step" id="alternate-step"></a>

1. Go to [Online Broken Link Checker](https://ahrefs.com/broken-link-checker), [Dead Link Checker](https://www.deadlinkchecker.com/) Or [Alternative Online Broken Link Checker](https://brokenlinkcheck.com/)
2. Input the domain name

#### Reference <a href="#reference" id="reference"></a>

* [https://edoverflow.com/2017/broken-link-hijacking/](https://edoverflow.com/2017/broken-link-hijacking/)
* [https://medium.com/@bathinivijaysimhareddy/how-i-takeover-the-companys-linkedin-page-790c9ed2b04d](https://medium.com/@bathinivijaysimhareddy/how-i-takeover-the-companys-linkedin-page-790c9ed2b04d)

**Impact**

Content Hijacking Information Leakage Phishing Attacks stored xss Impersonation Damage the company’s reputation
