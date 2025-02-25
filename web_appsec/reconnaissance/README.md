---
cover: >-
  https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.compuone.com%2Fthe-five-phases-of-penetration-testing%2F&psig=AOvVaw3Iez6_ktwsOlVjQtXb1-0S&ust=1720149332880000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCLCHieW1jIcDFQAAAAAdAAAAABAE
coverY: 0
---

# 😀 Reconnaissance

## "Hackers make the mistake of paying attention to the exploitation process, and neglecting the information gathering stage “

> **So i will talk about Reconnaissance ..**

## 💭 Whoami :

> **I'm\[ Abdelrahman Ali H3ckt00r] ,** Jr. Penetration Tester&#x20;

## 🛫 Plan

> Full simple Reconnaissance

### Most hackers, when they set a specific target, do not know where to start! So, let me explain my path in the reconnaissance process ..

## I am seeking to obtain the following:

My principle is from start to finish ..

> 1-IPs&#x20;
>
> 2-Subdomains&#x20;
>
> 3-Js Files
>
> 4-Directories
>
> 5-Parameters&#x20;
>
> 6-Emails

With the 6 elements, I can get 6 files, as a basic infrastructure for my reconnaissance project. Yes, this is only the basic stage and then I start the next phase..

Then, how do I get my project’s Infrastructure ?

***

## **1) AS Number :**

> Autonomous System Number (ASN) is a globally unique identifier that defines a group of one or more IP prefixes run by one or more network operators that maintain a single, clearly-defined routing policy. These groups of IP prefixes are known as autonomous systems. The ASN allows the autonomous systems to exchange routing information with other autonomous systems.

I can get the asn with several ways :

### 1) theHarvester

```bash
theHarvester -d [target.com](http://target.com/) -b all
```

### b) Amass

```bash
 amass enum -active -d [target.com](http://target.com/)
```

***

## **2) CIDR :**

> **After completing the previous stage, the stage of collecting the ASN of the target.. I will convert ASNs to CIDR group**

How i Resolve AS Number to CIDRs ..?

### a) whois

```bash
whois -h [whois.radb.net](http://whois.radb.net/) -- '-i origin AS16509' | grep -Eo "([0-9.]+){4}/[0-9]+" |uniq
```

#### 2- BGP

***

## **3) Network Sweeping :**

> **After completing the stage of collecting some CIDRs, I want to convert the CIDR to the IP Address .. whichever is host up or host down ?**

```bash
 nmap -n -sn 13.35.121.0/24 |grep "for" |cut -d " " -f 5 >> IP.txt (Host Descovery)
```

Now , i have File.txt containing Handreds of IP A , all of them is Host Up , .. but wait ..

#### Are all hosts down IP really host down? Or the firewall plays a malicious role?

> Normally, the firewall is blocking any requests, and the Host is Up but I see it as Host Down.. So, let's deceive this problem

We will perform the Port Scanning process, and then we will mark the Host Up ..

```bash
 nmap -n -Pn -sS 13.35.121.0/24 |grep "for" |cut -d " " -f 5 >> IP.txt
```

Now we Have IP.txt all of them is Host Up !

***

## **4- Subdomain Enumeration**

***

### (a) Subfinder

> Subfinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.

```bash
# Install
 go get github.com/subfinder/subfinder

# Basic usage
 subfinder -d example.com > example.com.subs

# Recursive
 subfinder -d  example.com  -recursive -silent -t 200 -o  example.com.subs

# Use censys for even more results
 subfinder -d example.com -b -w wordlist.txt -t 100 -sources censys -set-settings CensysPages=2 -v -o example.com.subs
```

• In the Subfinder Github Repository it was mentioned that some of the services will not work until you set it up.

• So i started looking into it to set-up the **config-file** with the API Keys that are mentioned to see what is the **major difference in the results of subdomain**

#### • Navigate to the following directory

```python
cd .config/subfinder/
```

`cat config.yaml` to see the config file

• We can see many of the API Key services are **Empty** , so now are going to fill the necessary API Keys as source for Subdomain Enumeration.

**Note** The below following API Keys are **Free Of Cost** and has a Limited number of request in it.

* binaryedge
* censys
* certspotter
* chaos
* dnsdb
* github
* intelx
* passivetotal
* robtex
* securitytrails
* shodan
* spyse
* urlscan
* virustotal
* zoomeye

**Binaryedge**

**1 :** [Sign up](https://app.binaryedge.io/sign-up) for a free account, and verify the account.

**2 :** Login into the account and Navigate to this URL [https://app.binaryedge.io/account/api](https://app.binaryedge.io/account/api) and give a name to the **TOKEN** and Click on Generate Token.



**Censys**

**1 :** [Sign up](https://censys.io/register) for a free account, and verify the account.

**2 :** Login into the account and Navigate to this URL [https://censys.io/account/api](https://censys.io/account/api) and you will be able to get **API ID** and **Secret**



**Certspotter**

**1 :** [Sign up](https://sslmate.com/signup?for=certspotter_api) for a free account.

**2 :** Login into the account and Navigate to this URL [https://sslmate.com/account/api\_credentials](https://sslmate.com/account/api_credentials) and you will be able to get the **API Key**

Note : 100 queries an hour is **free**.



**Chaos**

**1 :** Navigate to this URL [https://chaos.projectdiscovery.io/#/](https://chaos.projectdiscovery.io/#/)

**2 :** Early access is provided basis on signup and queue and Invite are send out Weekly basis.

**3 :** Contributor access is Provided on the basis of **PR** that is done under `github.com/projectdiscovery/*`.



**DNSdb**

**1 :** [Sign up](https://www.farsightsecurity.com/dnsdb-community-edition/) for a free community account.

**2 :** It will ask for Company Email , use [Temp Email](https://temp-mail.org/).

**3 :** Create an account and verify the email and get the **API Key**.

Note : It has 30-day renewal (with valid email confirmation)



**Github**

**1 :** [Sign up](https://github.com/join) for a free account, verify the account.

**2 :** Navigate to this URL [https://github.com/settings/tokens](https://github.com/settings/tokens) and generate a **Personal access tokens**.



**Intelx**

**1 :** [Sign up](https://intelx.io/signup) for a free account, verify the account.

**2 :** Navigate to this URL [https://intelx.io/account?tab=developer](https://intelx.io/account?tab=developer) and you will get the **API details**.

Note: Trial 1 week for Free



**Passivetotal**

**1 :** [Sign up](https://community.riskiq.com/home) for a free account, verify the account.

**2 :** Login into the account and Navigate to this URL [https://community.riskiq.com/settings](https://community.riskiq.com/settings) and you will be able to get **KEY** and **Secret** .



**Robtex**

**1 :** Sign in using the google **Gmail Account**

**2 :** Navigate to this URL [https://www.robtex.com/dashboard/](https://www.robtex.com/dashboard/) , you will get the **API-Key** details.



**Security Trails**

**1 :** [Sign up](https://securitytrails.com/app/signup) for a free account, verify the account.

**2 :** Login into the account and Navigate to this URL [https://securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials) and you will be able to get **API Key** .

Note : Monthly Quoto is 50 API Requests.



**Shodan**

**1 :** [Register](https://account.shodan.io/login) for a shodan account.

**2 :** Login into the account and navigate to this URL [https://account.shodan.io/](https://account.shodan.io/) , you will get the **API Key** details.



**Spyse**

**1 :** [Register](https://spyse.com/user/registration) for a Spyse account and verify it.

**2 :** Login into the account and navigate to this URL [https://spyse.com/user](https://spyse.com/user) , you will get the **API Token** details.

Note : It has 100 API Token valid for 5 days during the Trail Period.



**UrlScan**

**1 :** [Sign up](https://urlscan.io/user/signup) for a free account, verify the account.

**2 :** Login into the account and Navigate to this URL [https://urlscan.io/user/profile/](https://urlscan.io/user/profile/) and click on Create new **API Key**.



**Virustotal**

**1 :** [Register](https://www.virustotal.com/gui/join-us) for a Virustotal account and verify it.

**2 :** Login into the account and navigate to this URL [https://www.virustotal.com/gui/user/username/apikey](https://www.virustotal.com/gui/user/username/apikey) , you will get the **API Key** details.



**Zoom Eye**

**1 :** [Register](https://sso.telnet404.com/accounts/register/) for a ZoomEye account and verify it.

**2 :** Login into the account and navigate to this URL [https://www.zoomeye.org/profile](https://www.zoomeye.org/profile) , you will get the **API Key** details.

```
Now the Final Config File Looks Full!!!**
```

Now Let us compare the Results **Before** and **After** Adding API Keys.

**Before API Key**

<figure><img src="../../.gitbook/assets/sub23_(1).png" alt=""><figcaption></figcaption></figure>

**After API Key**

<figure><img src="../../.gitbook/assets/sub24 (1).png" alt=""><figcaption></figcaption></figure>

***

### (b) Amass

> The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

```bash
# passive
amass enum --passive -d example.com -o example.com.subs

# active
amass enum  -src -ip -brute -min-for-recursive 2 -d example.com -o example.com.subs
```

***

### (c) Assetfinder

> Find domains and subdomains related to a given domain

```bash
# Install
 go get -u github.com/tomnomnom/assetfinder

# Basic usage
 assetfinder [--subs-only] <domain>
```

***

### (d) GetAllUrls \[GAU]

> getallurls (gau) fetches known URLs from AlienVault's [Open Threat Exchange](https://otx.alienvault.com/), the Wayback Machine, Common Crawl, and URLScan for any given domain. Inspired by Tomnomnom's [waybackurls](https://github.com/tomnomnom/waybackurls).\*\*\*\*

```bash
# Install
go get -u -v github.com/lc/gau

# Extract subdomains from output
gau -subs example.com | cut -d / -f 3 | sort -u
```

***

### (e) SubEnum

> bash script for Subdomain Enumeration using 4 tools and 3 online services, you have to install these tools by yourself to be able to use SubEnum.sh, or use [setup.sh](https://github.com/bing0o/SubEnum/blob/master/setup.sh) script to install them.

```bash
# Install
 git clone https://github.com/bing0o/SubEnum.git
 cd SubEnum
 chmod +x setup.sh
./setup.sh

# Basic Usage
subenum -d target.com

#Agains List Of Domains
 subenum -l domains.txt -r
```

***

### (f) theHarvester

> theHarvester is a simple to use, yet powerful tool designed to be used during thereconnaissance stage of a red team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using multiple public resources

```bash
 theHarvester -d cisco.com -b all 
```

<figure><img src="../../.gitbook/assets/WhatsApp-Image-2020-05-15-at-8.16.23-PM (2).jpeg" alt=""><figcaption></figcaption></figure>

### (j) Favicon

> Did you know that we can find related domains and sub domains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

favihash - discover domains with the same favicon icon hash

Simply said, favihash will allow us to discover domains that have the same favicon icon hash as our target.

Moreover, you can also search technologies using the favicon hash as explained in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). That means that if you know the **hash of the favicon of a vulnerable version of a web tech** you can search if in shodan and **find more vulnerable places**:

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```

This is how you can **calculate the favicon hash** of a web:

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url)
    favicon = codecs.encode(response.content,"base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

### h) [https://CRT](https://crt).sh

```python
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

### 5) Filter Alive Hosts - Info - CName

#### a) Httpx

> `httpx` is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the [retryablehttp](https://github.com/projectdiscovery/retryablehttp-go) library. It is designed to maintain result reliability with an increased number of threads.

```python
# install
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Basic Usage
cat hosts.txt | httpx

# FIle Input
httpx -list hosts.txt -silent -probe
```

***

## **(5) Js Files - Directory - Parameters -&#x20;**~~**Robot**~~**.txt**

> And now this is the interesting stage for me, we will collect the following through only one tool :

* Js Files
* Directory
* Parameters
* Robot.txt

### (a) Yes, it's (gau) ..

> getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan for any given domain. Inspired by Tomnomnom's waybackurls.

```bash
# Install
go install github.com/lc/gau/v2/cmd/gau@latest

# Usage
printf example.com | gau
cat domains.txt | gau --threads 5
gau example.com google.com
gau --o example-urls.txt example.com
gau --blacklist png,jpg,gif example.com
```

### (b) Js Scanner

> Js File Scanner This is Js File Scanner . Which are scan in js file and find juicy information Toke,Password Etc.

```bash
# Install
git clone https://github.com/0x240x23elu/JSScanner.git
cd JSScanner
pip3 install -r  requirements.txt

# Usage
echo "example.com" | waybackurls | grep -iE '\.js'|grep -ivE '\.json'|sort -u  > j.txt
or
echo "example.com" | waybackurls | httpx > live.txt
```

***

### (c) GoSpider

> A fast web spider written in Go

```bash
# Install
go get -u github.com/jaeles-project/gospider

# Basic usage
# Run with single site
gospider -s "https://google.com/" -o output -c 10 -d 1

# Run with site list
gospider -S sites.txt -o output -c 10 -d 1

# Also get URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com) and include subdomains
gospider -s "https://google.com/" -o output -c 10 -d 1 --other-source --include-subs

# Blacklist url/file extension.
└─$ gospider -s "https://google.com/" -o output -c 10 -d 1 --blacklist ".(woff|pdf)"
```

### (d) Find all JS File

> JavaScipt files are always worth to have a look at. I always filter for URLs returning JavaScript files and I save them in an extra file for later.

> A great write-up about static JavaScript analysis can be found here:

> [Static Analysis of Client-Side JavaScript for pen testers and bug bounty hunters](https://blog.appsecco.com/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288?gi=e19a920a2344)

```bash
 cat urls.txt | grep "\.js" > js-urls.txt

# check, if they are actually available
 cat js-urls.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk | grep Status:200
```

***

### e) Katana

> **A next-generation crawling and spidering framework**

```python
# Install
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Basic Usage
katana -u https://tesla.com

# List Input
 cat url_list.txt

https://tesla.com
https://google.com

 katana -list url_list.txt

# See More 
https://github.com/projectdiscovery/katana
```

## _**6- Emails**_

> With the domains and subdomains inside the scope you basically have all what you need to start searching for emails. These are the APIs and tools that have worked the best for me to find emails of a company:

API of - [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) - with api API of - [https://hunter.io/](https://hunter.io/) - free version API of - [https://app.snov.io/](https://app.snov.io/) - free version API of - [https://minelead.io/](https://minelead.io/) - free version

Other :

```bash
python infoga.py --domain nsa.gov --source all --breach -v 2 --report ../nsa_gov.txt
theHarvester -d cisco.com -b all
amass enum -active -d grab.com
```

***

### _**Now we have the following:**_

* IPs.txt
* Subs.txt
* Urls\&Param.txt
* JsFile.txt
* Directory.txt
* Emails
* Robot.txt

<figure><img src="../../.gitbook/assets/Screenshot_from_2023-08-03_12-28-02.png" alt=""><figcaption></figcaption></figure>

***

***

## II) Brute-Force & Fuzzing

> **I call the previous stage " the basic infrastructure stage " , now let's start the second stage .. This stage is to fully complete what we started from the first stage.**

### 1) Subdomain Brute Force

> **Another active enumeration technique is called subdomain brute force, where large lists of subdomains are prepended to the target domain and sent to the resolver in order to retrieve DNS Resource Records (RR) like A for IPv4 addresses, CNAME for aliases or AAAA for IPv6 addresses.09‏/01‏/2023**

#### a) PureDNS

> Puredns is a fast domain resolver and subdomain bruteforcing tool that can accurately filter out wildcard subdomains and DNS poisoned entries.

```bash
# Prerequisites
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install

# Install
go install github.com/d3mondev/puredns/v2@latest

# Basic Usage
puredns bruteforce all.txt domain.com

#Multiple Domains
puredns bruteforce all.txt -d domains.txt
```

***

## 2) Directory Fuzzing

> **Directory fuzzing (a.k.a. directory bruteforcing) is a technique that can find some of those "hidden" paths. Dictionaries of common paths are used to request the web app for each path until exhaustion of the list. This technique relies on the attacker using a dictionnary/wordlist.**

First i want to resolve “target.com” to “https://target.com” , to Fuzzing Directory after \[.com].

### a) **httprobe**

> Take a list of domains and probe for working http and https servers.\*\*\*\*

```bash
# install
go install github.com/tomnomnom/httprobe@latest

# Basic Usage
cat subs.txt
example.com
example.edu
example.net
cat subs.txt | httprobe
http://example.com
http://example.net
http://example.edu
https://example.com
https://example.edu
https://example.net
```

### 2) FuFF

> A fast web fuzzer written in Go.

```bash
# Installation
go get github.com/ffuf/ffuf

# Basic usage
ffuf -w wordlist.txt -u https://example.com/FUZZ
# Hidden Dir
ffuf -w wordlist.txt -u https://example.com/_FUZZ

# Automatically calibrate filtering options
ffuf -w wordlist.txt -u https://example.com/FUZZ -ac
 
#FUZZ HOST HEADER
ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u  http://hackycorp.com/ -H "HOST: FUZZ.hackycrop.com"

# Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

# Fuzz from List of URLs
for URL in $(<urls.txt);do (fuff args[]);done
```

## **3) Parameter Fuzzing**

> Fuzz testing or fuzzing is **an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities**. A fuzzing tool injects these inputs into the system and then monitors for exceptions such as crashes or information leakage.

### a) Fuff

> A fast web fuzzer written in Go.

```bash
# Install
 git clone https://github.com/ffuf/ffuf ; cd ffuf ; go get ; go build

# GET Paraneter Fuzzing
 ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs <Number of Default Lenght>
"GET parameter name fuzzing is very similar to directory discovery, and works by defining the FUZZ keyword as a part of the URL. This also assumes a response size of 4242 bytes for invalid GET parameter name"

ffuf -w /path/to/values.txt -u https://target/script.php?valid_name=FUZZ -fc 401
"If the parameter name is known, the values can be fuzzed the same way. This example assumes a wrong parameter value returning HTTP response code 401"

# POST Data Fuzzing
ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401

"This is a very straightforward operation, again by using the FUZZ keyword. This example is fuzzing only part of the POST request. We're again filtering out the 401 responses"

"You should to read more about fuff" :
https://github.com/ffuf/ffuf

 ffuf -w params.txt -u http://ffuf.me/cd/param/data?FUZZ=1 -c true -s -t 99 -rate 660
 ffuf -request req.txt -w params.txt -c true -s -t 99 -rate 660 [in request param=FUZZ]
 ffuf -w params.txt -u http://ffuf.me/cd/param/data? -c true -s -t 99 -rate 660 -X PSOT -d '{"name": "FUZZ", "anotherkey": "anothervalue"}'
```

***

### b) Parampampam

> This tool for brute discover GET and POST parameters.

```bash
# Install
 git clone https://github.com/Bo0oM/ParamPamPam.git
 cd ParamPamPam
 pip3 install --no-cache-dir -r requirements.txt

# Usage
 python3 parampp.py -u "https://vk.com/login" -m GET -f getparamsout.txt
 python3 parampp.py -u "https://vk.com/login" -m POST -f postparamsout.txt
```

### c) arjun

> Arjun can find query parameters for URL endpoints. If you don't get what that means, it's okay, read along

```bash
# Install
 pip3 install arjun

# Scan a single URL
 arjun -u https://api.example.com/endpoint

# Import Targets
 arjun -i targets.txt

 arjun -i urls.txt -t 90 -oT getparams.txt  -w paramswordlist.txt -m GET  --stable  --disable-redirects --hraders "Accept-Language: en-US\nCookie: null"

 arjun -i urls.txt -t 90 -oT postparams.txt -w paramswordlist.txt -m POST  --stable  --disable-redirects --hraders "Accept-Language: en-US\nCookie: null"

# API (REST)
 arjun -i urls.txt -t 90 -oT jsonparams.txt -w paramswordlist.txt -m JSON  --stable  --disable-redirects --hraders "Accept-Language: en-US\nCookie: null"

# API (SOAP)
 arjun -i urls.txt -t 90 -oT soapparams.txt -w paramswordlist.txt -m XML --stable  --disable-redirects --hraders "Accept-Language: en-US\nCookie: null"
```

## 4) VHost Fuzzing

> some servers \[ 1 IP ] contain several hosts .. lets get them

### a) GoBuster

```python
gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt
```

### b) VHostScan

```python
VHostScan -t domain.com
```

***

Now, I have consolidated some of the previously collected files, There are only two steps left to complete these stages :

## 5) **Resolve IPs to Domains**

### a) HostHunter

> HostHunter a recon tool for discovering hostnames using OSINT techniques.
>
> [GitHub Link](https://github.com/SpiderLabs/HostHunter)
>
> (includes installation instructions)

```bash
# Basic usage
 python3 hosthunter.py <target-ips.txt> > vhosts.txt
```

### b) nmap

> i will not talk about nmap ,, ;)

```bash
 nmap -iL  ips.txt -sn | grep for |cut -d " " -f 5
```

### 6) Resolve Domains to IPs

> this is a simple line of bash

```bash
 for url in $(cat grab.txt); do host $url | grep "has address" | cut -d " " -f 4 ;done
```

***

## **III ) Dorks & Secrets & Leaks , Open Source Code**

### 1)Credintials Leaks

> With the domains, subdomains, and emails you can start looking for credentials leaked in the past belonging to those emails:

* [**Leak-lookup**](https://leak-lookup.com/account/login)
* [Dehashed](https://www.dehashed.com/)

***

### **2) Dorks**

> A dork query, sometimes just referred to as a _dork_, is a [search string](https://www.techtarget.com/whatis/definition/search-string) or custom [query](https://www.techtarget.com/searchdatamanagement/definition/query) that uses advanced [search operators](https://www.techtarget.com/whatis/definition/search-operator) to find information not readily available on a [website](https://www.techtarget.com/whatis/definition/Web-site).

#### a) GitHub Dorking With \[GitRob]

> Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github. Gitrob will clone repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files. The findings will be presented through a web interface for easy browsing and analysis.

```python
#install
 go get github.com/michenriksen/gitrob

# Usage
 gitrob [options] target [target2] ... [targetN]

# Options
-bind-address string
    Address to bind web server to (default "127.0.0.1")
-commit-depth int
    Number of repository commits to process (default 500)
-debug
    Print debugging information
-github-access-token string
    GitHub access token to use for API requests
-load string
    Load session file
-no-expand-orgs
    Don't add members to targets when processing organizations
-port int
    Port to run web server on (default 9393)
-save string
    Save session to file
-silent
    Suppress all output except for errors
-threads int
    Number of concurrent threads (default number of logical CPUs)
```

```python
GIthub Dorks

".mlab.com password"
"access_key"
"access_token"
"amazonaws"
"api.googlemaps AIza"
"api_key"
"api_secret"
"apidocs"
"apikey"
"apiSecret"
"app_key"
"app_secret"
"appkey"
"appkeysecret"
"application_key"
"appsecret"
"appspot"
"auth"
"auth_token"
"authorizationToken"
"aws_access"
"aws_access_key_id"
"aws_key"
"aws_secret"
"aws_token"
"AWSSecretKey"
"bashrc password"
"bucket_password"
"client_secret"
"cloudfront"
"codecov_token"
"config"
"conn.login"
"connectionstring"
"consumer_key"
"credentials"
"database_password"
"db_password"
"db_username"
"dbpasswd"
"dbpassword"
"dbuser"
"dot-files"
"dotfiles"
"encryption_key"
"fabricApiSecret"
"fb_secret"
"firebase"
"ftp"
"gh_token"
"github_key"
"github_token"
"gitlab"
"gmail_password"
"gmail_username"
"herokuapp"
"internal"
"irc_pass"
"JEKYLL_GITHUB_TOKEN"
"key"
"keyPassword"
"ldap_password"
"ldap_username"
"login"
"mailchimp"
"mailgun"
"master_key"
"mydotfiles"
"mysql"
"node_env"
"npmrc _auth"
"oauth_token"
"pass"
"passwd"
"password"
"passwords"
"pem private"
"preprod"
"private_key"
"prod"
"pwd"
"pwds"
"rds.amazonaws.com password"
"redis_password"
"root_password"
"secret"
"secret.password"
"secret_access_key"
"secret_key"
"secret_token"
"secrets"
"secure"
"security_credentials"
"send.keys"
"send_keys"
"sendkeys"
"SF_USERNAME salesforce"
"sf_username"
"site.com" FIREBASE_API_JSON=
"site.com" vim_settings.xml
"slack_api"
"slack_token"
"sql_password"
"ssh"
"ssh2_auth_password"
"sshpass"
"staging"
"stg"
"storePassword"
"stripe"
"swagger"
"testuser"
"token"
"x-api-key"
"xoxb "
"xoxp"
[WFClient] Password= extension:ica
access_key
bucket_password
dbpassword
dbuser
extension:avastlic "support.avast.com"
extension:bat
extension:cfg
extension:env
extension:exs
extension:ini
extension:json api.forecast.io
extension:json googleusercontent client_secret
extension:json mongolab.com
extension:pem
extension:pem private
extension:ppk
extension:ppk private
extension:properties
extension:sh
extension:sls
extension:sql
extension:sql mysql dump
extension:sql mysql dump password
extension:yaml mongolab.com
extension:zsh
filename:.bash_history
filename:.bash_history DOMAIN-NAME
filename:.bash_profile aws
filename:.bashrc mailchimp
filename:.bashrc password
filename:.cshrc
filename:.dockercfg auth
filename:.env DB_USERNAME NOT homestead
filename:.env MAIL_HOST=smtp.gmail.com
filename:.esmtprc password
filename:.ftpconfig
filename:.git-credentials
filename:.history
filename:.htpasswd
filename:.netrc password
filename:.npmrc _auth
filename:.pgpass
filename:.remote-sync.json
filename:.s3cfg
filename:.sh_history
filename:.tugboat NOT _tugboat
filename:_netrc password
filename:apikey
filename:bash
filename:bash_history
filename:bash_profile
filename:bashrc
filename:beanstalkd.yml
filename:CCCam.cfg
filename:composer.json
filename:config
filename:config irc_pass
filename:config.json auths
filename:config.php dbpasswd
filename:configuration.php JConfig password
filename:connections
filename:connections.xml
filename:constants
filename:credentials
filename:credentials aws_access_key_id
filename:cshrc
filename:database
filename:dbeaver-data-sources.xml
filename:deployment-config.json
filename:dhcpd.conf
filename:dockercfg
filename:environment
filename:express.conf
filename:express.conf path:.openshift
filename:filezilla.xml
filename:filezilla.xml Pass
filename:git-credentials
filename:gitconfig
filename:global
filename:history
filename:htpasswd
filename:hub oauth_token
filename:id_dsa
filename:id_rsa
filename:id_rsa or filename:id_dsa
filename:idea14.key
filename:known_hosts
filename:logins.json
filename:makefile
filename:master.key path:config
filename:netrc
filename:npmrc
filename:pass
filename:passwd path:etc
filename:pgpass
filename:prod.exs
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:proftpdpasswd
filename:recentservers.xml
filename:recentservers.xml Pass
filename:robomongo.json
filename:s3cfg
filename:secrets.yml password
filename:server.cfg
filename:server.cfg rcon password
filename:settings
filename:settings.py SECRET_KEY
filename:sftp-config.json
filename:sftp-config.json password
filename:sftp.json path:.vscode
filename:shadow
filename:shadow path:etc
filename:spec
filename:sshd_config
filename:token
filename:tugboat
filename:ventrilo_srv.ini
filename:WebServers.xml
filename:wp-config
filename:wp-config.php
filename:zhrc
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
HOMEBREW_GITHUB_API_TOKEN language:shell
jsforce extension:js conn.login
language:yaml -filename:travis
msg nickserv identify filename:config
org:Target "AWS_ACCESS_KEY_ID"
org:Target "list_aws_accounts"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "bucket_name"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_BUCKET"
org:Target "S3_ENDPOINT"
org:Target "S3_SECRET_ACCESS_KEY"
password
path:sites databases password
private -language:java
PT_TOKEN language:bash
redis_password
root_password
secret_access_key
SECRET_KEY_BASE=
shodan_api_key language:python
WORDPRESS_DB_PASSWORD=
xoxp OR xoxb OR xoxa
s3.yml
.exs
beanstalkd.yml
deploy.rake
.sls
AWS_SECRET_ACCESS_KEY
API KEY
API SECRET
API TOKEN
ROOT PASSWORD
ADMIN PASSWORD
GCP SECRET
AWS SECRET
"private" extension:pgp
# GitHub Dorking
## List
- 0dysAuQ5KQk=
- 0GITHUB_TOKEN=
- 0HB_CODESIGN_GPG_PASS=
- 0HB_CODESIGN_KEY_PASS=
- 0KNAME=
- 0NC6O0ThWq69BcWmrtbD2ev0UDivbG8OQ1ZsSDm9UqVA=
- 0PUSHOVER_TOKEN=
- 0PUSHOVER_USER=
- 0PYg1Q6Qa8BFHJDZ0E8F4thnPFDb1fPnUVIgfKmkE8mnLaQoO7JTHuvyhvyDA=
- 0VIRUSTOTAL_APIKEY=
- 0YhXFyQ=
- 1ewh8kzxY=
- 1LRQzo6ZDqs9V9RCMaGIy2t4bN3PAgMWdEJDoU1zhuy2V2AgeQGFzG4eanpYZQqAp6poV02DjegvkXC7cA5QrIcGZKdrIXLQk4TBXx2ZVigDio5gYLyrY=
- 2bS58p9zjyPk7aULCSAF7EUlqT041QQ5UBJV7gpIxFW1nyD6vL0ZBW1wA1k1PpxTjznPA=
- 3FvaCwO0TJjLU1b0q3Fc=
- 6EpEOjeRfE=
- 6mSMEHIauvkenQGZlBzkLYycWctGml9tRnIpbqJwv0xdrkTslVwDQU5IEJNZiTlJ2tYl8og=
- 6tr8Q=
- 7h6bUpWbw4gN2AP9qoRb6E6ITrJPjTZEsbSWgjC00y6VrtBHKoRFCU=
- 7QHkRyCbP98Yv2FTXrJFcx9isA2viFx2UxzTsvXcAKHbCSAw=
- 8FWcu69WE6wYKKyLyHB4LZHg=
- 8o=
- 9OcroWkc=
- 47WombgYst5ZcnnDFmUIYa7SYoxZAeCsCTySdyTso02POFAKYz5U=
- ".mlab.com password"
- "access_key"
- "access_token"
- "amazonaws"
- "api.googlemaps AIza"
- "api_key"
- "api_secret"
- "apidocs"
- "apikey"
- "apiSecret"
- "app_key"
- "app_secret"
- "appkey"
- "appkeysecret"
- "application_key"
- "appsecret"
- "appspot"
- "auth"
- "auth_token"
- "authorizationToken"
- "aws_access"
- "aws_access_key_id"
- "aws_key"
- "aws_secret"
- "aws_token"
- "AWSSecretKey"
- "bashrc password"
- "bucket_password"
- "client_secret"
- "cloudfront"
- "codecov_token"
- "config"
- "conn.login"
- "connectionstring"
- "consumer_key"
- "credentials"
- "database_password"
- "db_password"
- "db_username"
- "dbpasswd"
- "dbpassword"
- "dbuser"
- "dot-files"
- "dotfiles"
- "encryption_key"
- "fabricApiSecret"
- "fb_secret"
- "firebase"
- "ftp"
- "gh_token"
- "github_key"
- "github_token"
- "gitlab"
- "gmail_password"
- "gmail_username"
- "herokuapp"
- "internal"
- "irc_pass"
- "JEKYLL_GITHUB_TOKEN"
- "key"
- "keyPassword"
- "ldap_password"
- "ldap_username"
- "login"
- "mailchimp"
- "mailgun"
- "master_key"
- "mydotfiles"
- "mysql"
- "node_env"
- "npmrc _auth"
- "oauth_token"
- "pass"
- "passwd"
- "password"
- "passwords"
- "pem private"
- "preprod"
- "private_key"
- "prod"
- "pwd"
- "pwds"
- "rds.amazonaws.com password"
- "redis_password"
- "root_password"
- "secret"
- "secret.password"
- "secret_access_key"
- "secret_key"
- "secret_token"
- "secrets"
- "secure"
- "security_credentials"
- "send.keys"
- "send_keys"
- "sendkeys"
- "SF_USERNAME salesforce"
- "sf_username"
- "slack_api"
- "slack_token"
- "sql_password"
- "ssh2_auth_password"
- "ssh"
- "sshpass"
- "staging"
- "stg"
- "storePassword"
- "stripe"
- "swagger"
- "testuser"
- "token"
- "x-api-key"
- "xoxb"
- "xoxp"
- #=
- #N=
- &key=
- &noexp=
- &password=
- &pr=
- &project=
- &query=
- (\"client_secret\":\"[a-zA-Z0-9-_]{24}\")
- (xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})
- -----BEGIN DSA PRIVATE KEY-----
- -----BEGIN EC PRIVATE KEY-----
- -----BEGIN OPENSSH PRIVATE KEY-----
- -----BEGIN PGP PRIVATE KEY BLOCK-----
- -----BEGIN RSA PRIVATE KEY-----
- --branch=
- --closure_entry_point=
- --host=
- --ignore-ssl-errors=
- --org=
- --password=
- --port=
- --token=
- --username=
- -DdbUrl=
- -Dgpg.passphrase=
- -Dmaven.javadoc.skip=
- -DSELION_BROWSER_RUN_HEADLESS=
- -DSELION_DOWNLOAD_DEPENDENCIES=
- -DSELION_SELENIUM_RUN_LOCALLY=
- -DSELION_SELENIUM_USE_GECKODRIVER=
- -DskipTests=
- -Dsonar.login=
- -Dsonar.organization=
- -Dsonar.projectKey=
- -e=
- -p=
- -u=
- .mlab.com password
- [WFClient] Password= extension:ica
- \"type\": \"service_account\"
- \?access_token=
- \?AccessKeyId=
- \?account=
- \?id=
- _02ddd67d5586_key=
- _8382f1c42598_iv=
- a=
- aaaaaaa=
- ABC=
- acceptInsecureCerts=
- acceptSslCerts=
- ACCESS KEY ID	=
- ACCESS_KEY=
- ACCESS_KEY_ID=
- ACCESS_KEY_SECRET=
- ACCESS_SECRET=
- ACCESS_TOKEN=
- accessibilityChecks=
- ACCESSKEY=
- ACCESSKEYID=
- ACCOUNT_SID=
- ADMIN_EMAIL=
- ADZERK_API_KEY=
- AGFA=
- AiYPFLTRxoiZJ9j0bdHjGOffCMvotZhtc9xv0VXVijGdHiIM=
- AKIA[0-9A-Z]{16}
- ALARM_CRON=
- ALGOLIA_ADMIN_KEY_1=
- ALGOLIA_ADMIN_KEY_2=
- ALGOLIA_ADMIN_KEY_MCM=
- ALGOLIA_API_KEY=
- ALGOLIA_API_KEY_MCM=
- ALGOLIA_API_KEY_SEARCH=
- ALGOLIA_APP_ID=
- ALGOLIA_APP_ID_MCM=
- ALGOLIA_APPLICATION_ID=
- ALGOLIA_APPLICATION_ID_1=
- ALGOLIA_APPLICATION_ID_2=
- ALGOLIA_APPLICATION_ID_MCM=
- ALGOLIA_SEARCH_API_KEY=
- ALGOLIA_SEARCH_KEY=
- ALGOLIA_SEARCH_KEY_1=
- ALIAS_NAME=
- ALIAS_PASS=
- ALICLOUD_ACCESS_KEY=
- ALICLOUD_SECRET_KEY=
- amazon_bucket_name=
- AMAZON_SECRET_ACCESS_KEY=
- AMQP://GUEST:GUEST@=
- ANACONDA_TOKEN=
- ANALYTICS=
- ANDROID_DOCS_DEPLOY_TOKEN=
- android_sdk_license=
- android_sdk_preview_license=
- ANSIBLE_VAULT_PASSWORD=
- aos_key=
- aos_sec=
- API_KEY=
- API_KEY_MCM=
- API_KEY_SECRET=
- API_KEY_SID=
- API_SECRET=
- APIARY_API_KEY=
- APIGW_ACCESS_TOKEN=
- APP_BUCKET_PERM=
- APP_ID=
- APP_NAME=
- APP_REPORT_TOKEN_KEY=
- APP_SECRETE=
- APP_SETTINGS=
- APP_TOKEN=
- appClientSecret=
- APPLE_ID_PASSWORD=
- APPLE_ID_USERNAME=
- APPLICATION_ID=
- APPLICATION_ID_MCM=
- applicationCacheEnabled=
- ARGOS_TOKEN=
- ARTIFACTORY_KEY=
- ARTIFACTORY_USERNAME=
- ARTIFACTS
- ARTIFACTS_AWS_ACCESS_KEY_ID=
- ARTIFACTS_AWS_SECRET_ACCESS_KEY=
- ARTIFACTS_BUCKET=
- ARTIFACTS_KEY=
- ARTIFACTS_SECRET=
- ASSISTANT_IAM_APIKEY=
- ATOKEN=
- AURORA_STRING_URL=
- AUTH0_API_CLIENTID=
- AUTH0_API_CLIENTSECRET=
- AUTH0_AUDIENCE=
- AUTH0_CALLBACK_URL=
- AUTH0_CLIENT_ID=
- AUTH0_CLIENT_SECRET=
- AUTH0_CONNECTION=
- AUTH0_DOMAIN=
- AUTH=
- AUTH_TOKEN=
- AUTHOR_EMAIL_ADDR=
- AUTHOR_NPM_API_KEY=
- AVbcnrfDmp7k=
- AWS
- AWS-ACCT-ID=
- AWS-KEY=
- AWS-SECRETS=
- AWS.config.accessKeyId=
- AWS.config.secretAccessKey=
- AWS_ACCESS=
- AWS_ACCESS_KEY=
- AWS_ACCESS_KEY_ID=
- AWS_CF_DIST_ID=
- AWS_DEFAULT
- AWS_DEFAULT_REGION=
- AWS_S3_BUCKET=
- AWS_SECRET=
- AWS_SECRET_ACCESS_KEY=
- AWS_SECRET_KEY=
- AWS_SES_ACCESS_KEY_ID=
- AWS_SES_SECRET_ACCESS_KEY=
- AWSACCESSKEYID=
- AWSCN_ACCESS_KEY_ID=
- AWSCN_SECRET_ACCESS_KEY=
- AWSSECRETKEY=
- aX5xTOsQFzwacdLtlNkKJ3K64=
- B2_ACCT_ID=
- B2_APP_KEY=
- B2_BUCKET=
- baseUrlTravis=
- BINTRAY_API_KEY=
- BINTRAY_APIKEY=
- BINTRAY_GPG_PASSWORD=
- BINTRAY_KEY=
- BINTRAY_TOKEN=
- BINTRAY_USER=
- bintrayKey=
- bintrayUser=
- BLhLRKwsTLnPm8=
- BLUEMIX
- BLUEMIX_ACCOUNT=
- BLUEMIX_API_KEY=
- BLUEMIX_AUTH=
- BLUEMIX_NAMESPACE=
- BLUEMIX_ORG=
- BLUEMIX_ORGANIZATION=
- BLUEMIX_PASS=
- BLUEMIX_PASS_PROD=
- BLUEMIX_PASSWORD=
- BLUEMIX_PWD=
- BLUEMIX_SPACE=
- BLUEMIX_USER=
- BLUEMIX_USERNAME=
- BRACKETS_REPO_OAUTH_TOKEN=
- branch=
- BROWSER_STACK_ACCESS_KEY=
- BROWSER_STACK_USERNAME=
- browserConnectionEnabled=
- BROWSERSTACK_ACCESS_KEY=
- BROWSERSTACK_BUILD=
- BROWSERSTACK_PARALLEL_RUNS=
- BROWSERSTACK_PROJECT_NAME=
- BROWSERSTACK_USE_AUTOMATE=
- BROWSERSTACK_USERNAME=
- BUCKETEER_AWS_ACCESS_KEY_ID=
- BUCKETEER_AWS_SECRET_ACCESS_KEY=
- BUCKETEER_BUCKET_NAME=
- BUILT_BRANCH_DEPLOY_KEY=
- BUNDLE_GEM__ZDSYS__COM=
- BUNDLE_GEMS__CONTRIBSYS__COM=
- BUNDLE_ZDREPO__JFROG__IO=
- BUNDLESIZE_GITHUB_TOKEN=
- BX_PASSWORD=
- BX_USERNAME=
- BXIAM=
- BzwUsjfvIM=
- c6cBVFdks=
- c=
- cacdc=
- CACHE_S3_SECRET_KEY=
- CACHE_URL=
- CARGO_TOKEN=
- casc=
- CASPERJS_TIMEOUT=
- CATTLE_ACCESS_KEY=
- CATTLE_AGENT_INSTANCE_AUTH=
- CATTLE_SECRET_KEY=
- CC_TEST_REPORTER_ID=
- CC_TEST_REPOTER_ID=
- cdascsa=
- cdscasc=
- CENSYS_SECRET=
- CENSYS_UID=
- CERTIFICATE_OSX_P12=
- CERTIFICATE_PASSWORD=
- CF_ORGANIZATION=
- CF_PASSWORD=
- CF_PROXY_HOST=
- CF_SPACE=
- CF_USERNAME=
- channelId=
- CHEVERNY_TOKEN=
- CHROME_CLIENT_ID=
- CHROME_CLIENT_SECRET=
- CHROME_EXTENSION_ID=
- CHROME_REFRESH_TOKEN=
- CI_DEPLOY_PASSWORD=
- CI_DEPLOY_USER=
- CI_DEPLOY_USERNAME=
- CI_NAME=
- CI_PROJECT_NAMESPACE=
- CI_PROJECT_URL=
- CI_REGISTRY_USER=
- CI_SERVER_NAME=
- CI_USER_TOKEN=
- CLAIMR_DATABASE=
- CLAIMR_DB=
- CLAIMR_SUPERUSER=
- CLAIMR_TOKEN=
- CLI_E2E_CMA_TOKEN=
- CLI_E2E_ORG_ID=
- CLIENT_ID=
- CLIENT_SECRET=
- clojars_password=
- clojars_username=
- CLOUD_API_KEY=
- CLOUDAMQP_URL=
- CLOUDANT_APPLIANCE_DATABASE=
- CLOUDANT_ARCHIVED_DATABASE=
- CLOUDANT_AUDITED_DATABASE=
- CLOUDANT_DATABASE=
- CLOUDANT_INSTANCE=
- CLOUDANT_ORDER_DATABASE=
- CLOUDANT_PARSED_DATABASE=
- CLOUDANT_PASSWORD=
- CLOUDANT_PROCESSED_DATABASE=
- CLOUDANT_SERVICE_DATABASE=
- CLOUDANT_USERNAME=
- CLOUDFLARE_API_KEY=
- CLOUDFLARE_AUTH_EMAIL=
- CLOUDFLARE_AUTH_KEY=
- CLOUDFLARE_CREVIERA_ZONE_ID=
- CLOUDFLARE_EMAIL=
- CLOUDFLARE_ZONE_ID=
- CLOUDFRONT_DISTRIBUTION_ID=
- CLOUDINARY_URL=
- CLOUDINARY_URL_EU=
- CLOUDINARY_URL_STAGING=
- CLU_REPO_URL=
- CLU_SSH_PRIVATE_KEY_BASE64=
- CLUSTER=
- CLUSTER_NAME=
- CN_ACCESS_KEY_ID=
- CN_SECRET_ACCESS_KEY=
- COCOAPODS_TRUNK_EMAIL=
- COCOAPODS_TRUNK_TOKEN=
- CODACY_PROJECT_TOKEN=
- CODECLIMATE_REPO_TOKEN=
- CODECOV_TOKEN=
- coding_token=
- COMPONENT=
- CONEKTA_APIKEY=
- CONFIGURATION_PROFILE_SID=
- CONFIGURATION_PROFILE_SID_P2P=
- CONFIGURATION_PROFILE_SID_SFU=
- CONSUMER_KEY=
- CONSUMERKEY=
- CONTENTFUL_ACCESS_TOKEN=
- CONTENTFUL_CMA_TEST_TOKEN=
- CONTENTFUL_INTEGRATION_MANAGEMENT_TOKEN=
- CONTENTFUL_INTEGRATION_SOURCE_SPACE=
- CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN=
- CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN_NEW=
- CONTENTFUL_ORGANIZATION=
- CONTENTFUL_PHP_MANAGEMENT_TEST_TOKEN=
- CONTENTFUL_TEST_ORG_CMA_TOKEN=
- CONTENTFUL_V2_ACCESS_TOKEN=
- CONTENTFUL_V2_ORGANIZATION=
- CONVERSATION_PASSWORD=
- CONVERSATION_URL=
- CONVERSATION_USERNAME=
- COREAPI_HOST=
- COS_SECRETS=
- COVERALLS_API_TOKEN=
- COVERALLS_REPO_TOKEN=
- COVERALLS_SERVICE_NAME=
- COVERALLS_TOKEN=
- COVERITY_SCAN_NOTIFICATION_EMAIL=
- COVERITY_SCAN_TOKEN=
- cred=
- csac=
- cssSelectorsEnabled=
- cTjHuw0saao68eS5s=
- CXQEvvnEow=
- CYPRESS_RECORD_KEY=
- DANGER_GITHUB_API_TOKEN=
- DANGER_VERBOSE=
- DATABASE_HOST=
- DATABASE_NAME=
- DATABASE_PASSWORD=
- DATABASE_PORT=
- DATABASE_USER=
- DATABASE_USERNAME=
- databaseEnabled=
- datadog_api_key=
- datadog_app_key=
- DB_CONNECTION=
- DB_DATABASE=
- DB_HOST=
- DB_PASSWORD=
- DB_PORT=
- DB_PW=
- DB_USER=
- DB_USERNAME=
- DBP=
- DDG_TEST_EMAIL=
- DDG_TEST_EMAIL_PW=
- DDGC_GITHUB_TOKEN=
- DEPLOY_DIR=
- DEPLOY_DIRECTORY=
- DEPLOY_HOST=
- DEPLOY_PASSWORD=
- DEPLOY_PORT=
- DEPLOY_SECURE=
- DEPLOY_TOKEN=
- DEPLOY_USER=
- DEST_TOPIC=
- DH_END_POINT_1=
- DH_END_POINT_2=
- DHL_SOLDTOACCOUNTID=
- DIGITALOCEAN_ACCESS_TOKEN=
- DIGITALOCEAN_SSH_KEY_BODY=
- DIGITALOCEAN_SSH_KEY_IDS=
- DOCKER-REGISTRY=
- DOCKER=
- DOCKER_EMAIL=
- DOCKER_HUB_PASSWORD=
- DOCKER_HUB_USERNAME=
- DOCKER_KEY=
- DOCKER_PASS=
- DOCKER_PASSWD=
- DOCKER_PASSWORD=
- DOCKER_POSTGRES_URL=
- DOCKER_RABBITMQ_HOST=
- docker_repo=
- DOCKER_TOKEN=
- DOCKER_USER=
- DOCKER_USERNAME=
- DOCKERHUB_PASSWORD=
- dockerhubPassword=
- dockerhubUsername=
- DOORDASH_AUTH_TOKEN=
- DRIVER_NAME=
- DROPBOX=
- DROPBOX_OAUTH_BEARER=
- DROPLET_TRAVIS_PASSWORD=
- duration=
- dv3U5tLUZ0=
- DXA=
- ELASTIC_CLOUD_AUTH=
- ELASTIC_CLOUD_ID=
- ELASTICSEARCH_HOST=
- ELASTICSEARCH_PASSWORD=
- ELASTICSEARCH_USERNAME=
- email=
- EMAIL_NOTIFICATION=
- ENCRYPTION_PASSWORD=
- END_USER_PASSWORD=
- END_USER_USERNAME=
- ensureCleanSession=
- env.GITHUB_OAUTH_TOKEN=
- env.HEROKU_API_KEY=
- env.SONATYPE_PASSWORD=
- env.SONATYPE_USERNAME=
- ENV_KEY=
- ENV_SDFCAcctSDO_QuipAcctVineetPersonal=
- ENV_SECRET=
- ENV_SECRET_ACCESS_KEY=
- eureka.awsAccessId=
- eureka.awsSecretKey=
- ExcludeRestorePackageImports=
- EXP_PASSWORD=
- EXP_USERNAME=
- EXPORT_SPACE_ID=
- extension:avastlic "support.avast.com"
- extension:bat
- extension:cfg
- extension:env
- extension:exs
- extension:ini
- extension:json api.forecast.io
- extension:json googleusercontent client_secret
- extension:json mongolab.com
- extension:pem
- extension:pem private
- extension:ppk
- extension:ppk private
- extension:properties
- extension:sh
- extension:sls
- extension:sql
- extension:sql mysql dump
- extension:sql mysql dump password
- extension:yaml mongolab.com
- extension:zsh
- EXTENSION_ID=
- EZiLkw9g39IgxjDsExD2EEu8U9jyz8iSmbKsrK6Z4L3BWO6a0gFakBAfWR1Rsb15UfVPYlJgPwtAdbgQ65ElgVeyTdkDCuE64iby2nZeP4=
- F97qcq0kCCUAlLjAoyJg=
- FACEBOOK=
- FBTOOLS_TARGET_PROJECT=
- FDfLgJkS3bKAdAU24AS5X8lmHUJB94=
- FEEDBACK_EMAIL_RECIPIENT=
- FEEDBACK_EMAIL_SENDER=
- FI1_RECEIVING_SEED=
- FI1_SIGNING_SEED=
- FI2_RECEIVING_SEED=
- FI2_SIGNING_SEED=
- FILE_PASSWORD=
- filename:.bash_history
- filename:.bash_profile aws
- filename:.bashrc mailchimp
- filename:.bashrc password
- filename:.cshrc
- filename:.dockercfg auth
- filename:.env DB_USERNAME NOT homestead
- filename:.env MAIL_HOST=smtp.gmail.com
- filename:.esmtprc password
- filename:.ftpconfig
- filename:.git-credentials
- filename:.history
- filename:.htpasswd
- filename:.netrc password
- filename:.npmrc _auth
- filename:.pgpass
- filename:.remote-sync.json
- filename:.s3cfg
- filename:.sh_history
- filename:.tugboat NOT _tugboat
- filename:_netrc password
- filename:bash
- filename:bash_history
- filename:bash_profile
- filename:bashrc
- filename:beanstalkd.yml
- filename:CCCam.cfg
- filename:composer.json
- filename:config
- filename:config irc_pass
- filename:config.json auths
- filename:config.php dbpasswd
- filename:config.php pass
- filename:configuration.php JConfig password
- filename:connections
- filename:connections.xml
- filename:constants
- filename:credentials
- filename:credentials aws_access_key_id
- filename:cshrc
- filename:database
- filename:dbeaver-data-sources.xml
- filename:deploy.rake
- filename:deployment-config.json
- filename:dhcpd.conf
- filename:dockercfg
- filename:environment
- filename:express.conf
- filename:express.conf path:.openshift
- filename:filezilla.xml
- filename:filezilla.xml Pass
- filename:git-credentials
- filename:gitconfig
- filename:global
- filename:history
- filename:htpasswd
- filename:hub oauth_token
- filename:id_dsa
- filename:id_rsa
- filename:id_rsa or - filename:id_dsa
- filename:id_rsa or filename:id_dsa
- filename:idea14.key
- filename:known_hosts
- filename:logins.json
- filename:makefile
- filename:master.key path:config
- filename:netrc
- filename:npmrc
- filename:pass
- filename:passwd path:etc
- filename:pgpass
- filename:prod.exs
- filename:prod.exs NOT prod.secret.exs
- filename:prod.secret.exs
- filename:proftpdpasswd
- filename:recentservers.xml
- filename:recentservers.xml Pass
- filename:robomongo.json
- filename:s3cfg
- filename:secrets.yml password
- filename:server.cfg
- filename:server.cfg rcon password
- filename:settings
- filename:settings.py SECRET_KEY
- filename:sftp-config.json
- filename:sftp.json path:.vscode
- filename:shadow
- filename:shadow path:etc
- filename:spec
- filename:sshd_config
- filename:tugboat
- filename:ventrilo_srv.ini
- filename:WebServers.xml
- filename:wp-config
- filename:wp-config.php
- filename:zhrc
- FIREBASE_API_JSON=
- FIREBASE_API_TOKEN=
- FIREBASE_KEY=
- FIREBASE_PROJECT=
- FIREBASE_PROJECT_DEVELOP=
- FIREBASE_PROJECT_ID=
- FIREBASE_SERVICE_ACCOUNT=
- FIREBASE_TOKEN=
- FIREFOX_CLIENT=
- FIREFOX_ISSUER=
- FIREFOX_SECRET=
- FLASK_SECRET_KEY=
- FLICKR=
- FLICKR_API_KEY=
- FLICKR_API_SECRET=
- FOO=
- FOSSA_API_KEY=
- fR457Xg1zJIz2VcTD5kgSGAPfPlrYx2xnR5yILYiaWiLqQ1rhFKQZ0rwOZ8Oiqk8nPXkSyXABr9B8PhCFJGGKJIqDI39Qe6XCXAN3GMH2zVuUDfgZCtdQ8KtM1Qg71IR4g=
- ftp_host=
- FTP_LOGIN=
- FTP_PASSWORD=
- FTP_PW=
- FTP_USER=
- ftp_username=
- fvdvd=
- gateway=
- GCLOUD_BUCKET=
- GCLOUD_PROJECT=
- GCLOUD_SERVICE_KEY=
- GCR_PASSWORD=
- GCR_USERNAME=
- GCS_BUCKET=
- ggFqFEKCd54gCDasePLTztHeC4oL104iaQ=
- GH_API_KEY=
- GH_EMAIL=
- GH_NAME=
- GH_NEXT_OAUTH_CLIENT_ID=
- GH_NEXT_OAUTH_CLIENT_SECRET=
- GH_NEXT_UNSTABLE_OAUTH_CLIENT_ID=
- GH_NEXT_UNSTABLE_OAUTH_CLIENT_SECRET=
- GH_OAUTH_CLIENT_ID=
- GH_OAUTH_CLIENT_SECRET=
- GH_OAUTH_TOKEN=
- GH_REPO_TOKEN=
- GH_TOKEN=
- GH_UNSTABLE_OAUTH_CLIENT_ID=
- GH_UNSTABLE_OAUTH_CLIENT_SECRET=
- GH_USER_EMAIL=
- GH_USER_NAME=
- GHB_TOKEN=
- GHOST_API_KEY=
- GIT_AUTHOR_EMAIL=
- GIT_AUTHOR_NAME=
- GIT_COMMITTER_EMAIL=
- GIT_COMMITTER_NAME=
- GIT_EMAIL=
- GIT_NAME=
- GIT_TOKEN=
- GIT_USER=
- GITHUB_ACCESS_TOKEN=
- GITHUB_API_KEY=
- GITHUB_API_TOKEN=
- GITHUB_AUTH=
- GITHUB_AUTH_TOKEN=
- GITHUB_AUTH_USER=
- GITHUB_CLIENT_ID=
- GITHUB_CLIENT_SECRET=
- GITHUB_DEPLOY_HB_DOC_PASS=
- GITHUB_DEPLOYMENT_TOKEN=
- GITHUB_HUNTER_TOKEN=
- GITHUB_HUNTER_USERNAME=
- GITHUB_KEY=
- GITHUB_OAUTH=
- GITHUB_OAUTH_TOKEN=
- GITHUB_PASSWORD=
- GITHUB_PWD=
- GITHUB_RELEASE_TOKEN=
- GITHUB_REPO=
- GITHUB_TOKEN=
- GITHUB_TOKENS=
- GITHUB_USER=
- GITHUB_USERNAME=
- GITLAB_USER_EMAIL=
- GITLAB_USER_LOGIN=
- GK_LOCK_DEFAULT_BRANCH=
- GOGS_PASSWORD=
- GOOGLE_ACCOUNT_TYPE=
- GOOGLE_CLIENT_EMAIL=
- GOOGLE_CLIENT_ID=
- GOOGLE_CLIENT_SECRET=
- GOOGLE_MAPS_API_KEY=
- GOOGLE_PRIVATE_KEY=
- GOOGLEAPIS.COM/=
- GOOGLEUSERCONTENT.COM=
- gpg.passphrase=
- GPG_EMAIL=
- GPG_ENCRYPTION=
- GPG_EXECUTABLE=
- GPG_KEY_NAME=
- GPG_KEYNAME=
- GPG_NAME=
- GPG_OWNERTRUST=
- GPG_PASSPHRASE=
- GPG_PRIVATE_KEY=
- GPG_SECRET_KEYS=
- gradle.publish.key=
- gradle.publish.secret=
- GRADLE_SIGNING_KEY_ID=
- GRADLE_SIGNING_PASSWORD=
- GREN_GITHUB_TOKEN=
- GRGIT_USER=
- groupToShareTravis=
- HAB_AUTH_TOKEN=
- HAB_KEY=
- handlesAlerts=
- hasTouchScreen=
- HB_CODESIGN_GPG_PASS=
- HB_CODESIGN_KEY_PASS=
- HEROKU_API_KEY language:json
- HEROKU_API_KEY language:shell
- HEROKU_API_KEY=
- HEROKU_API_USER=
- HEROKU_EMAIL=
- HEROKU_TOKEN=
- HOCKEYAPP_TOKEN=
- HOMEBREW_GITHUB_API_TOKEN language:shell
- HOMEBREW_GITHUB_API_TOKEN=
- HOOKS.SLACK.COM=
- HOST=
- hpmifLs=
- Hso3MqoJfx0IdpnYbgvRCy8zJWxEdwJn2pC4BoQawJx8OgNSx9cjCuy6AH93q2zcQ=
- https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}
- HUB_DXIA2_PASSWORD=
- Hxm6P0NESfV0whrZHyVOaqIRrbhUsK9j4YP8IMFoI4qYp4g=
- I6SEeHdMJwAvqM6bNXQaMJwJLyZHdAYK9DQnY=
- ibCWoWs74CokYVA=
- id=
- IJ_REPO_PASSWORD=
- IJ_REPO_USERNAME=
- IMAGE=
- INDEX_NAME=
- INSTAGRAM=
- INTEGRATION_TEST_API_KEY=
- INTEGRATION_TEST_APPID=
- INTERNAL-SECRETS=
- IOS_DOCS_DEPLOY_TOKEN=
- IRC_NOTIFICATION_CHANNEL=
- isbooleanGood=
- ISDEVELOP=
- isParentAllowed=
- iss=
- ISSUER=
- ITEST_GH_TOKEN=
- java.net.UnknownHostException=
- javascriptEnabled=
- JDBC:MYSQL=
- jdbc_databaseurl=
- jdbc_host=
- jdbc_user=
- JEKYLL_GITHUB_TOKEN
- jsforce - extension:js conn.login
- jsforce extension:js conn.login
- JWT_SECRET=
- jxoGfiQqqgvHtv4fLzI=
- KAFKA_ADMIN_URL=
- KAFKA_INSTANCE_NAME=
- KAFKA_REST_URL=
- KEY=
- KEYID=
- KEYSTORE_PASS=
- KOVAN_PRIVATE_KEY=
- KUBECFG_S3_PATH=
- KUBECONFIG=
- KXOlTsN3VogDop92M=
- language:yaml -- filename:travis
- LEANPLUM_APP_ID=
- LEANPLUM_KEY=
- LEKTOR_DEPLOY_PASSWORD=
- LEKTOR_DEPLOY_USERNAME=
- LICENSES_HASH=
- LICENSES_HASH_TWO=
- LIGHTHOUSE_API_KEY=
- LINKEDIN_CLIENT_ID=
- LINKEDIN_CLIENT_SECRET=
- LINODE_INSTANCE_ID=
- LINODE_VOLUME_ID=
- LINUX_SIGNING_KEY=
- LL_API_SHORTNAME=
- LL_PUBLISH_URL=
- LL_SHARED_KEY=
- LL_USERNAME=
- LOCATION_ID=
- locationContextEnabled=
- LOGNAME=
- LOGOUT_REDIRECT_URI=
- LOOKER_TEST_RUNNER_CLIENT_ID=
- LOOKER_TEST_RUNNER_CLIENT_SECRET=
- LOOKER_TEST_RUNNER_ENDPOINT=
- LOTTIE_HAPPO_API_KEY=
- LOTTIE_HAPPO_SECRET_KEY=
- LOTTIE_S3_API_KEY=
- LOTTIE_S3_SECRET_KEY=
- LOTTIE_UPLOAD_CERT_KEY_PASSWORD=
- LOTTIE_UPLOAD_CERT_KEY_STORE_PASSWORD=
- lr7mO294=
- MADRILL=
- MAGENTO_AUTH_PASSWORD=
- MAGENTO_AUTH_USERNAME=
- MAGENTO_PASSWORD=
- MAGENTO_USERNAME=
- MAIL_PASSWORD=
- MAIL_USERNAME=
- mailchimp_api_key=
- MAILCHIMP_KEY=
- mailchimp_list_id=
- mailchimp_user=
- MAILER_HOST=
- MAILER_PASSWORD=
- MAILER_TRANSPORT=
- MAILER_USER=
- MAILGUN_API_KEY=
- MAILGUN_APIKEY=
- MAILGUN_DOMAIN=
- MAILGUN_PASSWORD=
- MAILGUN_PRIV_KEY=
- MAILGUN_PUB_APIKEY=
- MAILGUN_PUB_KEY=
- MAILGUN_SECRET_API_KEY=
- MAILGUN_TESTDOMAIN=
- MANAGE_KEY=
- MANAGE_SECRET=
- MANAGEMENT_TOKEN=
- ManagementAPIAccessToken=
- MANDRILL_API_KEY=
- MANIFEST_APP_TOKEN=
- MANIFEST_APP_URL=
- MAPBOX_ACCESS_TOKEN=
- MAPBOX_API_TOKEN=
- MAPBOX_AWS_ACCESS_KEY_ID=
- MAPBOX_AWS_SECRET_ACCESS_KEY=
- MapboxAccessToken=
- marionette=
- MAVEN_STAGING_PROFILE_ID=
- MG_API_KEY=
- MG_DOMAIN=
- MG_EMAIL_ADDR=
- MG_EMAIL_TO=
- MG_PUBLIC_API_KEY=
- MG_SPEND_MONEY=
- MG_URL=
- MH_APIKEY=
- MH_PASSWORD=
- MILE_ZERO_KEY=
- MINIO_ACCESS_KEY=
- MINIO_SECRET_KEY=
- mMmMSl1qNxqsumNhBlmca4g=
- mobileEmulationEnabled=
- MONGO_SERVER_ADDR=
- MONGOLAB_URI=
- mRFSU97HNZZVSvAlRxyYP4Xxx1qXKfRXBtqnwVJqLvK6JTpIlh4WH28ko=
- msg nickserv identify - filename:config
- msg nickserv identify filename:config
- MULTI_ALICE_SID=
- MULTI_BOB_SID=
- MULTI_CONNECT_SID=
- MULTI_DISCONNECT_SID=
- MULTI_WORKFLOW_SID=
- MULTI_WORKSPACE_SID=
- MY_SECRET_ENV=
- MYSQL_DATABASE=
- MYSQL_HOSTNAME=
- MYSQL_PASSWORD=
- MYSQL_ROOT_PASSWORD=
- MYSQL_USER=
- MYSQL_USERNAME=
- MYSQLMASTERUSER=
- MYSQLSECRET=
- n8awpV01A2rKtErnlJWVzeDK5WfLBaXUvOoc=
- nativeEvents=
- NETLIFY_API_KEY=
- NETLIFY_SITE_ID=
- networkConnectionEnabled=
- NEW_RELIC_BETA_TOKEN=
- NEXUS_PASSWORD=
- NEXUS_USERNAME=
- nexusPassword=
- nexusUrl=
- nexusUsername=
- NfZbmLlaRTClBvI=
- NGROK_AUTH_TOKEN=
- NGROK_TOKEN=
- NODE_ENV=
- node_pre_gyp_accessKeyId=
- NODE_PRE_GYP_GITHUB_TOKEN=
- node_pre_gyp_secretAccessKey=
- NON_MULTI_ALICE_SID=
- NON_MULTI_BOB_SID=
- NON_MULTI_CONNECT_SID=
- NON_MULTI_DISCONNECT_SID=
- NON_MULTI_WORKFLOW_SID=
- NON_MULTI_WORKSPACE_SID=
- NON_TOKEN=
- NOW_TOKEN=
- NPM_API_KEY=
- NPM_API_TOKEN=
- NPM_AUTH_TOKEN=
- NPM_CONFIG_AUDIT=
- NPM_CONFIG_STRICT_SSL=
- NPM_EMAIL=
- NPM_PASSWORD=
- NPM_SECRET_KEY=
- NPM_TOKEN=
- NPM_USERNAME=
- NQc8MDWYiWa1UUKW1cqms=
- NtkUXxwH10BDMF7FMVlQ4zdHQvyZ0=
- NUGET_API_KEY=
- NUGET_APIKEY=
- NUGET_KEY=
- NUMBERS_SERVICE=
- NUMBERS_SERVICE_PASS=
- NUMBERS_SERVICE_USER=
- NUNIT=
- OAUTH_TOKEN=
- OBJECT_STORAGE
- OBJECT_STORAGE_INCOMING_CONTAINER_NAME=
- OBJECT_STORAGE_PASSWORD=
- OBJECT_STORAGE_PROJECT_ID=
- OBJECT_STORAGE_USER_ID=
- OBJECT_STORE_BUCKET=
- OBJECT_STORE_CREDS=
- OC_PASS=
- OCTEST_APP_PASSWORD=
- OCTEST_APP_USERNAME=
- OCTEST_PASSWORD=
- OCTEST_SERVER_BASE_URL=
- OCTEST_SERVER_BASE_URL_2=
- OCTEST_USERNAME=
- OFTA
- OFTA_KEY=
- OFTA_SECRET=
- oFYEk7ehNjGZC268d7jep5p5EaJzch5ai14=
- OKTA_AUTHN_ITS_MFAENROLLGROUPID=
- OKTA_CLIENT_ORG_URL=
- OKTA_CLIENT_ORGURL=
- OKTA_CLIENT_TOKEN=
- OKTA_DOMAIN=
- OKTA_OAUTH2_CLIENT_ID=
- OKTA_OAUTH2_CLIENT_SECRET=
- OKTA_OAUTH2_CLIENTID=
- OKTA_OAUTH2_CLIENTSECRET=
- OKTA_OAUTH2_ISSUER=
- OMISE_KEY=
- OMISE_PKEY=
- OMISE_PUBKEY=
- OMISE_SKEY=
- ONESIGNAL_API_KEY=
- ONESIGNAL_USER_AUTH_KEY=
- OPEN_WHISK_KEY=
- OPENWHISK_KEY=
- org.gradle.daemon=
- ORG=
- ORG_GRADLE_PROJECT_cloudinary.url=
- ORG_GRADLE_PROJECT_cloudinaryUrl=
- ORG_GRADLE_PROJECT_SONATYPE_NEXUS_PASSWORD=
- ORG_GRADLE_PROJECT_SONATYPE_NEXUS_USERNAME=
- ORG_ID=
- ORG_PROJECT_GRADLE_SONATYPE_NEXUS_PASSWORD=
- ORG_PROJECT_GRADLE_SONATYPE_NEXUS_USERNAME=
- OS
- OS_AUTH_URL=
- OS_PASSWORD=
- OS_PROJECT_NAME=
- OS_TENANT_ID=
- OS_TENANT_NAME=
- OS_USERNAME=
- OSSRH_JIRA_PASSWORD=
- OSSRH_JIRA_USERNAME=
- OSSRH_PASS=
- OSSRH_PASSWORD=
- OSSRH_SECRET=
- OSSRH_USER=
- OSSRH_USERNAME=
- p8qojUzqtAhPMbZ8mxUtNukUI3liVgPgiMss96sG0nTVglFgkkAkEjIMFnqMSKnTfG812K4jIhp2jCO2Q3NeI=
- PACKAGECLOUD_TOKEN=
- PAGERDUTY=
- PAGERDUTY_APIKEY=
- PAGERDUTY_ESCALATION_POLICY_ID=
- PAGERDUTY_FROM_USER=
- PAGERDUTY_PRIORITY_ID=
- PAGERDUTY_SERVICE_ID=
- PANTHEON_SITE=
- PARSE_APP_ID=
- PARSE_JS_KEY=
- PASS=
- PASSWORD=
- passwordTravis=
- PAT=
- path:sites databases password
- PATH=
- PAYPAL_CLIENT_ID=
- PAYPAL_CLIENT_SECRET=
- PERCY_PROJECT=
- PERCY_TOKEN=
- PERSONAL_KEY=
- PERSONAL_SECRET=
- PG_DATABASE=
- PG_HOST=
- pHCbGBA8L7a4Q4zZihD3HA=
- PHP_BUILT_WITH_GNUTLS=
- PLACES_API_KEY=
- PLACES_APIKEY=
- PLACES_APPID=
- PLACES_APPLICATION_ID=
- PLOTLY_APIKEY=
- PLOTLY_USERNAME=
- PLUGIN_PASSWORD=
- PLUGIN_USERNAME=
- pLytpSCciF6t9NqqGZYbBomXJLaG84=
- POLL_CHECKS_CRON=
- POLL_CHECKS_TIMES=
- PORT=
- POSTGRES_ENV_POSTGRES_DB=
- POSTGRES_ENV_POSTGRES_PASSWORD=
- POSTGRES_ENV_POSTGRES_USER=
- POSTGRES_PORT=
- POSTGRESQL_DB=
- POSTGRESQL_PASS=
- PREBUILD_AUTH=
- preferred_username=
- PRING.MAIL.USERNAME=
- private -language:java
- PRIVATE_SIGNING_PASSWORD=
- PROD.ACCESS.KEY.ID=
- PROD.SECRET.KEY=
- PROD_BASE_URL_RUNSCOPE=
- PROD_PASSWORD=
- PROD_USERNAME=
- PROJECT_CONFIG=
- props.disabled=
- PT_TOKEN language:bash
- PUBLISH_ACCESS=
- PUBLISH_KEY=
- PUBLISH_SECRET=
- PUSHOVER_TOKEN=
- PUSHOVER_USER=
- PYPI_PASSOWRD=
- PYPI_PASSWORD=
- PYPI_USERNAME=
- Q67fq4bD04RMM2RJAS6OOYaBF1skYeJCblwUk=
- Q=
- QIITA=
- QIITA_TOKEN=
- qQ=
- query=
- QUIP_TOKEN=
- RABBITMQ_PASSWORD=
- RABBITMQ_SERVER_ADDR=
- raisesAccessibilityExceptions=
- RANDRMUSICAPIACCESSTOKEN=
- rBezlxWRroeeKcM2DQqiEVLsTDSyNZV9kVAjwfLTvM=
- rds.amazonaws.com password
- REDIRECT_URI=
- REDIS_STUNNEL_URLS=
- REDISCLOUD_URL=
- REFRESH_TOKEN=
- RELEASE_GH_TOKEN=
- RELEASE_TOKEN=
- remoteUserToShareTravis=
- REPO=
- REPORTING_WEBDAV_PWD=
- REPORTING_WEBDAV_URL=
- REPORTING_WEBDAV_USER=
- repoToken=
- REST_API_KEY=
- RestoreUseCustomAfterTargets=
- rI=
- RINKEBY_PRIVATE_KEY=
- RND_SEED=
- ROPSTEN_PRIVATE_KEY=
- rotatable=
- route53_access_key_id=
- RTD_ALIAS=
- RTD_KEY_PASS=
- RTD_STORE_PASS=
- rTwPXE9XlKoTn9FTWnAqF3MuWaLslDcDKYEh7OaYJjF01piu6g4Nc=
- RUBYGEMS_AUTH_TOKEN=
- RUNSCOPE_TRIGGER_ID=
- S3-EXTERNAL-3.AMAZONAWS.COM=
- S3.AMAZONAWS.COM=
- s3_access_key=
- S3_ACCESS_KEY_ID=
- S3_BUCKET_NAME_APP_LOGS=
- S3_BUCKET_NAME_ASSETS=
- S3_KEY=
- S3_KEY_APP_LOGS=
- S3_KEY_ASSETS=
- S3_PHOTO_BUCKET=
- S3_SECRET_APP_LOGS=
- S3_SECRET_ASSETS=
- S3_SECRET_KEY=
- S3_USER_ID=
- S3_USER_SECRET=
- SACLOUD_ACCESS_TOKEN=
- SACLOUD_ACCESS_TOKEN_SECRET=
- SACLOUD_API=
- SALESFORCE_BULK_TEST_PASSWORD=
- SALESFORCE_BULK_TEST_SECURITY_TOKEN=
- SALESFORCE_BULK_TEST_USERNAME=
- SALT=
- SANDBOX_ACCESS_TOKEN=
- SANDBOX_AWS_ACCESS_KEY_ID=
- SANDBOX_AWS_SECRET_ACCESS_KEY=
- SANDBOX_LOCATION_ID=
- SAUCE_ACCESS_KEY=
- SAUCE_USERNAME=
- scope=
- SCRUTINIZER_TOKEN=
- SDM4=
- sdr-token=
- SECRET ACCESS KEY=
- SECRET=
- SECRET_0=
- SECRET_1=
- SECRET_2=
- SECRET_3=
- SECRET_4=
- SECRET_5=
- SECRET_6=
- SECRET_7=
- SECRET_8=
- SECRET_9=
- SECRET_10=
- SECRET_11=
- SECRET_KEY_BASE=
- SECRETACCESSKEY=
- SECRETKEY=
- SEGMENT_API_KEY=
- SELION_LOG_LEVEL_DEV=
- SELION_LOG_LEVEL_USER=
- SELION_SELENIUM_HOST=
- SELION_SELENIUM_PORT=
- SELION_SELENIUM_SAUCELAB_GRID_CONFIG_FILE=
- SELION_SELENIUM_USE_SAUCELAB_GRID=
- SENDGRID=
- SENDGRID_API_KEY=
- SENDGRID_FROM_ADDRESS=
- SENDGRID_KEY=
- SENDGRID_PASSWORD=
- SENDGRID_USER=
- SENDGRID_USERNAME=
- SENDWITHUS_KEY=
- SENTRY_AUTH_TOKEN=
- SENTRY_DEFAULT_ORG=
- SENTRY_ENDPOINT=
- SERVERAPI_SERVER_ADDR=
- SERVICE_ACCOUNT_SECRET=
- SES_ACCESS_KEY=
- SES_SECRET_KEY=
- setDstAccessKey=
- setDstSecretKey=
- setSecretKey=
- setWindowRect=
- SF_USERNAME salesforce
- SGcUKGqyoqKnUg=
- shodan_api_key language:json
- shodan_api_key language:python
- shodan_api_key language:ruby
- shodan_api_key language:shell
- SIGNING_KEY=
- SIGNING_KEY_PASSWORD=
- SIGNING_KEY_SECRET=
- SIGNING_KEY_SID=
- SK[a-z0-9]{32}
- SLACK_CHANNEL=
- SLACK_ROOM=
- SLACK_WEBHOOK_URL=
- SLASH_DEVELOPER_SPACE=
- SLASH_DEVELOPER_SPACE_KEY=
- SLATE_USER_EMAIL=
- SNOOWRAP_CLIENT_ID=
- SNOOWRAP_CLIENT_SECRET=
- SNOOWRAP_PASSWORD=
- SNOOWRAP_REDIRECT_URI=
- SNOOWRAP_REFRESH_TOKEN=
- SNOOWRAP_USER_AGENT=
- SNOOWRAP_USERNAME=
- SNYK_API_TOKEN=
- SNYK_ORG_ID=
- SNYK_TOKEN=
- SOCRATA_APP_TOKEN=
- SOCRATA_PASSWORD=
- SOCRATA_USER=
- SOCRATA_USERNAME=
- SOME_VAR=
- SOMEVAR=
- SONA_TYPE_NEXUS_USERNAME=
- SONAR_ORGANIZATION_KEY=
- SONAR_PROJECT_KEY=
- SONAR_TOKEN=
- SONATYPE_GPG_KEY_NAME=
- SONATYPE_GPG_PASSPHRASE=
- SONATYPE_NEXUS_PASSWORD=
- SONATYPE_NEXUS_USERNAME=
- SONATYPE_PASS=
- SONATYPE_PASSWORD=
- SONATYPE_TOKEN_PASSWORD=
- SONATYPE_TOKEN_USER=
- SONATYPE_USER=
- SONATYPE_USERNAME=
- sonatypePassword=
- sonatypeUsername=
- SOUNDCLOUD_CLIENT_ID=
- SOUNDCLOUD_CLIENT_SECRET=
- SOUNDCLOUD_PASSWORD=
- SOUNDCLOUD_USERNAME=
- SPA_CLIENT_ID=
- SPACE=
- SPACES_ACCESS_KEY_ID=
- SPACES_SECRET_ACCESS_KEY=
- SPOTIFY_API_ACCESS_TOKEN=
- SPOTIFY_API_CLIENT_ID=
- SPOTIFY_API_CLIENT_SECRET=
- SPRING.MAIL.PASSWORD=
- SQS_NOTIFICATIONS_INTERNAL=
- sqsAccessKey=
- sqsSecretKey=
- SQUARE_READER_SDK_REPOSITORY_PASSWORD=
- SRC_TOPIC=
- SRCCLR_API_TOKEN=
- SSHPASS=
- SSMTP_CONFIG=
- STAGING_BASE_URL_RUNSCOPE=
- STAR_TEST_AWS_ACCESS_KEY_ID=
- STAR_TEST_BUCKET=
- STAR_TEST_LOCATION=
- STAR_TEST_SECRET_ACCESS_KEY=
- STARSHIP_ACCOUNT_SID=
- STARSHIP_AUTH_TOKEN=
- STORMPATH_API_KEY_ID=
- STORMPATH_API_KEY_SECRET=
- STRIP_PUBLISHABLE_KEY=
- STRIP_SECRET_KEY=
- STRIPE_PRIVATE=
- STRIPE_PUBLIC=
- SUBDOMAIN=
- SURGE_LOGIN=
- SURGE_TOKEN=
- SVN_PASS=
- SVN_USER=
- takesElementScreenshot=
- takesHeapSnapshot=
- takesScreenshot=
- TCfbCZ9FRMJJ8JnKgOpbUW7QfvDDnuL4YOPHGcGb6mG413PZdflFdGgfcneEyLhYI8SdlU=
- TEAM_EMAIL=
- ted_517c5824cb79_iv=
- TESCO_API_KEY=
- test=
- TEST_GITHUB_TOKEN=
- TEST_TEST=
- tester_keys_password=
- THERA_OSS_ACCESS_ID=
- THERA_OSS_ACCESS_KEY=
- TN8HHBZB9CCFozvq4YI5jS7oSznjTFIf1fJM=
- TOKEN=
- token_core_java=
- TRAVIS_ACCESS_TOKEN=
- TRAVIS_API_TOKEN=
- TRAVIS_BRANCH=
- TRAVIS_COM_TOKEN=
- TRAVIS_E2E_TOKEN=
- TRAVIS_GH_TOKEN=
- TRAVIS_PULL_REQUEST=
- TRAVIS_SECURE_ENV_VARS=
- TRAVIS_TOKEN=
- TREX_CLIENT_ORGURL=
- TREX_CLIENT_TOKEN=
- TREX_OKTA_CLIENT_ORGURL=
- TREX_OKTA_CLIENT_TOKEN=
- TRIGGER_API_COVERAGE_REPORTER=
- TRV=
- TWILIO_ACCOUNT_ID=
- TWILIO_ACCOUNT_SID=
- TWILIO_API_KEY=
- TWILIO_API_SECRET=
- TWILIO_CHAT_ACCOUNT_API_SERVICE=
- TWILIO_CONFIGURATION_SID=
- TWILIO_SID=
- TWILIO_TOKEN=
- TWILO=
- TWINE_PASSWORD=
- TWINE_USERNAME=
- TWITTER=
- TWITTER_CONSUMER_KEY=
- TWITTER_CONSUMER_SECRET=
- TWITTEROAUTHACCESSSECRET=
- TWITTEROAUTHACCESSTOKEN=
- UAusaB5ogMoO8l2b773MzgQeSmrLbExr9BWLeqEfjC2hFgdgHLaQ=
- udKwT156wULPMQBacY=
- uiElement=
- uk=
- UNITY_PASSWORD=
- UNITY_SERIAL=
- UNITY_USERNAME=
- URBAN_KEY=
- URBAN_MASTER_SECRET=
- URBAN_SECRET=
- URL=
- US-EAST-1.ELB.AMAZONAWS.COM=
- USABILLA_ID=
- USE_SAUCELABS=
- USE_SSH=
- user=
- USER_ASSETS_ACCESS_KEY_ID=
- USER_ASSETS_SECRET_ACCESS_KEY=
- USERNAME=
- userToShareTravis=
- userTravis=
- UzhH1VoXksrNQkFfc78sGxD0VzLygdDJ7RmkZPeBiHfX1yilToi1yrlRzRDLo46LvSEEiawhTa1i9W3UGr3p4LNxOxJr9tR9AjUuIlP21VEooikAhRf35qK0=
- V3GNcE1hYg=
- V_SFDC_CLIENT_ID=
- V_SFDC_CLIENT_SECRET=
- V_SFDC_PASSWORD=
- V_SFDC_USERNAME=
- VAULT_ADDR=
- VAULT_APPROLE_SECRET_ID=
- VAULT_PATH=
- VIP_GITHUB_BUILD_REPO_DEPLOY_KEY=
- VIP_GITHUB_DEPLOY_KEY=
- VIP_GITHUB_DEPLOY_KEY_PASS=
- VIP_TEST=
- VIRUSTOTAL_APIKEY=
- VISUAL_RECOGNITION_API_KEY=
- VSCETOKEN=
- VU8GYF3BglCxGAxrMW9OFpuHCkQ=
- vzG6Puz8=
- WAKATIME_API_KEY=
- WAKATIME_PROJECT=
- WATSON_CLIENT=
- WATSON_CONVERSATION_PASSWORD=
- WATSON_CONVERSATION_USERNAME=
- WATSON_CONVERSATION_WORKSPACE=
- WATSON_DEVICE=
- WATSON_DEVICE_PASSWORD=
- WATSON_DEVICE_TOPIC=
- WATSON_PASSWORD=
- WATSON_TEAM_ID=
- WATSON_TOPIC=
- WATSON_USERNAME=
- WEB_CLIENT_ID=
- webdavBaseUrlTravis=
- WEBHOOK_URL=
- webStorageEnabled=
- WIDGET_BASIC_PASSWORD=
- WIDGET_BASIC_PASSWORD_2=
- WIDGET_BASIC_PASSWORD_3=
- WIDGET_BASIC_PASSWORD_4=
- WIDGET_BASIC_PASSWORD_5=
- WIDGET_BASIC_USER=
- WIDGET_BASIC_USER_2=
- WIDGET_BASIC_USER_3=
- WIDGET_BASIC_USER_4=
- WIDGET_BASIC_USER_5=
- WIDGET_FB_PASSWORD=
- WIDGET_FB_PASSWORD_2=
- WIDGET_FB_PASSWORD_3=
- WIDGET_FB_USER=
- WIDGET_FB_USER_2=
- WIDGET_FB_USER_3=
- WIDGET_TEST_SERVER=
- WINCERT_PASSWORD=
- WORDPRESS_DB_PASSWORD=
- WORDPRESS_DB_USER=
- WORKSPACE_ID=
- WPJM_PHPUNIT_GOOGLE_GEOCODE_API_KEY=
- WPORG_PASSWORD=
- WPT_DB_HOST=
- WPT_DB_NAME=
- WPT_DB_PASSWORD=
- WPT_DB_USER=
- WPT_PREPARE_DIR=
- WPT_REPORT_API_KEY=
- WPT_SSH_CONNECT=
- WPT_SSH_PRIVATE_KEY_BASE64=
- WPT_TEST_DIR=
- WsleZEJBve7AFYPzR1h6Czs072X4sQlPXedcCHRhD48WgbBX0IfzTiAYCuG0=
- WvETELcH2GqdnVPIHO1H5xnbJ8k=
- WVNmZ40V1Lt0DYC2c6lzWwiJZFsQIXIRzJcubcwqKRoMelkbmKHdeIk=
- WWW.GOOGLEAPIS.COM=
- XJ7lElT4Jt9HnUw=
- xoxp OR xoxb
- xsax=
- xsixFHrha3gzEAwa1hkOw6kvzR4z9dx0XmpvORuo1h4Ag0LCxAR70ZueGyStqpaXoFmTWB1z0WWwooAd0kgDwMDSOcH60Pv4mew=
- Y8=
- YANGSHUN_GH_PASSWORD=
- YANGSHUN_GH_TOKEN=
- YEi8xQ=
- YHrvbCdCrtLtU=
- YO0=
- Yszo3aMbp2w=
- YT_ACCOUNT_CHANNEL_ID=
- YT_ACCOUNT_CLIENT_ID=
- YT_ACCOUNT_CLIENT_SECRET=
- YT_ACCOUNT_REFRESH_TOKEN=
- YT_API_KEY=
- YT_CLIENT_ID=
- YT_CLIENT_SECRET=
- YT_PARTNER_CHANNEL_ID=
- YT_PARTNER_CLIENT_ID=
- YT_PARTNER_CLIENT_SECRET=
- YT_PARTNER_ID=
- YT_PARTNER_REFRESH_TOKEN=
- YT_SERVER_API_KEY=
- YVxUZIA4Cm9984AxbYJGSk=
- zendesk-travis-github=
- zenSonatypePassword=
- zenSonatypeUsername=
- zf3iG1I1lI8pU=
- zfp2yZ8aP9FHSy5ahNjqys4FtubOWLk=
- ZHULIANG_GH_TOKEN=
- ZOPIM_ACCOUNT_KEY=
- ZZiigPX7RCjq5XHbzUpPpMbC8MFxT2K3jcFXUitfwZvNaZXJIiK3ZQJU4ayKaegLvI91x1SqH0=
plJ2V12nLpOPwY6zTtzcoTxEN6wcvUJfHAdNovpp63hWTnbAbEZamIdxwyCqpzThDobeD354TeXFUaKvrUw00iAiIhGL2QvwapaCbhlwM6NQAmdU3tMy3nZpka6bRI1kjyTh7CXfd- wXV98ZJSiPdUFxyIgFNI2dKiL3BI1pvFDfq3mnmi3WqzZHCaQqDKNEtUrzxC40swIJGLcLUiqc5xX37P47jNDWrNIRDs8IdbM0tS9pFM=
```

***

### b) Google Dorking

> **Google hacking**, also named **Google dorking**,is a [hacker](https://en.wikipedia.org/wiki/Hacker_\(computer_security\)) technique that uses Google Search and other [Google](https://en.wikipedia.org/wiki/Google) applications to find security holes in the [configuration](https://en.wikipedia.org/wiki/Computer_configuration) and computer code that [websites](https://en.wikipedia.org/wiki/Website) are using.

#### I ) GooFuzz

> **GooFuzz** is a script written in _Bash Scripting_ that uses advanced Google search techniques to obtain sensitive information in files or directories without making requests to the web server.\*\*\*\*

```python
# Install
 git clone https://github.com/m3n0sd0n4ld/GooFuzz.git
 cd GooFuzz
 chmod +x GooFuzz
 ./GooFuzz -h

# Lists files by extensions separated by commas.
GooFuzz -t nasa.gov -e pdf,bak,old -d 10

# Lists files by extensions contained in a txt file.
GooFuzz -t nasa.gov -e wordlists/extensions.txt -d 30

# List files, directories and even parameters by means of a wordlist (it is recommended to use only very small files).
GooFuzz -t nasa.gov -w wordlists/words-100.txt -p 3
```

#### II ) DorkGen

> Dorkgen is a dork query wrapper for popular search engines such as Google Search, DuckDuckGo, Yahoo and Bing. [Learn more about Google Hacking](https://en.wikipedia.org/wiki/Google_hacking). The goal of this package is to provide simple interfaces to creates valid dork queries for various search engines. This library was initially created for [**PhoneInfoga**](https://github.com/sundowndev/PhoneInfoga).

```python
# Install
go get github.com/sundowndev/dorkgen
```

```python
# Usage
package main

import "github.com/sundowndev/dorkgen"

func main() {
  dork := dorkgen.NewGoogleSearch()
  // dork := dorkgen.NewDuckDuckGo()
  // dork := dorkgen.NewBingSearch()
  // dork := dorkgen.NewYahooSearch()

  dork.Site("example.com").InText("text").String()
  // returns: site:example.com intext:"text"
}
```

```python
# Operators
func main() {
  dork.Site("facebook.com").Or().Site("twitter.com").String()
  // returns: site:facebook.com | site:twitter.com

  dork.InText("facebook").And().InText("twitter").String()
  // returns: intext:"facebook" + intext:"twitter"
}
```

Check this great tool : ‣

#### III ) Pentest-Tool

[Google Hacking - Free Google Dorks for Recon](https://pentest-tools.com/information-gathering/google-hacking)

```
inurl:example.com intitle:"index of"
inurl:example.com intitle:"index of /" "*key.pem"
inurl:example.com ext:log
inurl:example.com intitle:"index of" ext:sql|xls|xml|json|csv
inurl:example.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git
inurl:example.com intitle:"index of" "config.db"
inurl:example.com allintext:"API_SECRET*" ext:env | ext:yml
inurl:example.com intext:admin ext:sql inurl:admin
inurl:example.com allintext:username,password filetype:log site:example.com "-----BEGIN RSA PRIVATE KEY-----" - inurl:id_rsa
site:codepad.co "keyword"
site:scribd.com "keyword"
site:npmjs.com "keyword"
site:npm-runkit.com "keyword"
site:libraries.io "keyword"
site:ycombinator.io "keyword"
site:coggle.it "keyword"
site:papaly.com "keyword"
site:google.com "keyword"
site:trello.com "keyword"
site:prezi.com "keyword"
site:jsdelivr.net "keyword"
site:codepen.io "keyword"
site:codeshare.io "keyword"
site:sharecode.io "keyword"
site:pastebin.com "keyword"
site:repl.it "keyword"
site:productforums.google.com "keyword"
site:gitter.im "keyword"
site:bitbucket.org "keyword"
site:*atlassian.net "keyword"
inurl:gitlab "keyword"
inurl:github "keyword"
```

## Shodan Dorks

#### City:



Find devices in a particular city.

```
city:"Bangalore"
```

#### Country:



Find devices in a particular country.

```
country:"IN"
```

#### Geo:



Find devices by giving geographical coordinates.

```
geo:"56.913055,118.250862"
```

#### Location



```
country:us
country:ru
city:chicago
country:ru country:de city:chicago
```

#### Hostname:



Find devices matching the hostname.

```
server: "gws" hostname:"google"
hostname:example.com
hostname:example.com,example.org
```

#### Net:



Find devices based on an IP address or /x CIDR.

```
net:210.214.0.0/16
```

#### Organization



```
org:microsoft
org:"United States Department"
```

#### Autonomous System Number (ASN)



```
asn:ASxxxx
```

#### OS:



Find devices based on operating system.

```
os:"windows 7"
```

#### Port:



Find devices based on open ports.

```
proftpd port:21
```

#### Before/after:



Find devices before or after between a given time.

```
apache after:22/02/2009 before:14/3/2010
```

#### SSL/TLS Certificates



* Self signed certificates

```
ssl.cert.issuer.cn:example.com ssl.cert.subject.cn:example.com
```

* Expired certificates

```
ssl.cert.expired:true
ssl.cert.subject.cn:example.com
```

#### Device Type



```
device:firewall
device:router
device:wap
device:webcam
device:media
device:"broadband router"
device:pbx
device:printer
device:switch
device:storage
device:specialized
device:phone
device:"voip phone"
device:"voip adaptor"
device:"load balancer"
device:"print server"
device:terminal
device:remote
device:telecom
device:power
device:proxy
device:pda
device:bridge
```

#### Operating System



```
os:"windows 7"
os:"windows server 2012"
os:"linux 3.x"
```

#### Product



```
product:apache
product:nginx
product:android
product:chromecast
```

#### Customer Premises Equipment (CPE)



```
cpe:apple
cpe:microsoft
cpe:nginx
cpe:cisco
```

#### Server



```
server: nginx
server: apache
server: microsoft
server: cisco-ios
```

#### ssh fingerprints



```
dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0
```

### Web



#### Pulse Secure



```
http.html:/dana-na
```

#### PEM Certificates



```
http.title:"Index of /" http.html:".pem"
```

### Databases



#### MySQL



```
"product:MySQL"
```

#### MongoDB



```
"product:MongoDB"
```

#### elastic



```
port:9200 json
```

#### Memcached



```
"product:Memcached"
```

#### CouchDB



```
"product:CouchDB"
```

#### PostgreSQL



```
"port:5432 PostgreSQL"
```

#### Riak



```
"port:8087 Riak"
```

#### Redis



```
"product:Redis"
```

#### Cassandra



```
"product:Cassandra"
```

### Industrial Control Systems



#### Samsung Electronic Billboards



```
"Server: Prismview Player"
```

#### Gas Station Pump Controllers



```
"in-tank inventory" port:10001
```

#### Fuel Pumps connected to internet:



No auth required to access CLI terminal.

```
"privileged command" GET
```

#### Automatic License Plate Readers



```
P372 "ANPR enabled"
```

#### Traffic Light Controllers / Red Light Cameras



```
mikrotik streetlight
```

#### Voting Machines in the United States



```
"voter system serial" country:US
```

#### Open ATM:



```
May allow for ATM Access availability
NCR Port:"161"
```

#### Telcos Running Cisco Lawful Intercept Wiretaps



```
"Cisco IOS" "ADVIPSERVICESK9_LI-M"
```

#### Prison Pay Phones



```
"[2J[H Encartele Confidential"
```

#### Tesla PowerPack Charging Status



```
http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2
```

#### Electric Vehicle Chargers



```
"Server: gSOAP/2.8" "Content-Length: 583"
```

#### Maritime Satellites



Shodan made a pretty sweet Ship Tracker that maps ship locations in real time, too!

```
"Cobham SATCOM" OR ("Sailor" "VSAT")
```

#### Submarine Mission Control Dashboards



```
title:"Slocum Fleet Mission Control"
```

#### CAREL PlantVisor Refrigeration Units



```
"Server: CarelDataServer" "200 Document follows"
```

#### Nordex Wind Turbine Farms



```
http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1; Servlet 2.2; java 1.6.0_14)"
```

#### C4 Max Commercial Vehicle GPS Trackers



```
"[1m[35mWelcome on console"
```

#### DICOM Medical X-Ray Machines



Secured by default, thankfully, but these 1,700+ machines still have no business being on the internet.

```
"DICOM Server Response" port:104
```

#### GaugeTech Electricity Meters



```
"Server: EIG Embedded Web Server" "200 Document follows"
```

#### Siemens Industrial Automation



```
"Siemens, SIMATIC" port:161
```

#### Siemens HVAC Controllers



```
"Server: Microsoft-WinCE" "Content-Length: 12581"
```

#### Door / Lock Access Controllers



```
"HID VertX" port:4070
```

#### Railroad Management



```
"log off" "select the appropriate"
```

#### Tesla Powerpack charging Status:



Helps to find the charging status of tesla powerpack.

```
http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2
```

#### XZERES Wind Turbine



```
title:"xzeres wind"
```

#### PIPS Automated License Plate Reader



```
"html:"PIPS Technology ALPR Processors""
```

#### Modbus



```
"port:502"
```

#### Niagara Fox



```
"port:1911,4911 product:Niagara"
```

#### GE-SRTP



```
"port:18245,18246 product:"general electric""
```

#### MELSEC-Q



```
"port:5006,5007 product:mitsubishi"
```

#### CODESYS



```
"port:2455 operating system"
```

#### S7



```
"port:102"
```

#### BACnet



```
"port:47808"
```

#### HART-IP



```
"port:5094 hart-ip"
```

#### Omron FINS



```
"port:9600 response code"
```

#### IEC 60870-5-104



```
"port:2404 asdu address"
```

#### DNP3



```
"port:20000 source address"
```

#### EtherNet/IP



```
"port:44818"
```

#### PCWorx



```
"port:1962 PLC"
```

#### Crimson v3.0



```
"port:789 product:"Red Lion Controls"
```

#### ProConOS



```
"port:20547 PLC"
```

### Remote Desktop



#### Unprotected VNC



```
"authentication disabled" port:5900,5901
"authentication disabled" "RFB 003.008"
```

#### Windows RDP



99.99% are secured by a secondary Windows login screen.

```
"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"
```

### Network Infrastructure



#### Hacked routers:



Routers which got compromised

```
hacked-router-help-sos
```

#### Redis open instances



```
product:"Redis key-value store"
```

#### Citrix:



Find Citrix Gateway.

```
title:"citrix gateway"
```

#### Weave Scope Dashboards



Command-line access inside Kubernetes pods and Docker containers, and real-time visualization/monitoring of the entire infrastructure.

```
title:"Weave Scope" http.favicon.hash:567176827
```

#### MongoDB



Older versions were insecure by default. Very scary.

```
"MongoDB Server Information" port:27017 -authentication
```

#### Mongo Express Web GUI



Like the infamous phpMyAdmin but for MongoDB.

```
"Set-Cookie: mongo-express=" "200 OK"
```

#### Jenkins CI



```
"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"
```

#### Jenkins:



Jenkins Unrestricted Dashboard

```
x-jenkins 200
```

#### Docker APIs



```
"Docker Containers:" port:2375
```

#### Docker Private Registries



```
"Docker-Distribution-Api-Version: registry" "200 OK" -gitlab
```

#### Pi-hole Open DNS Servers



```
"dnsmasq-pi-hole" "Recursion: enabled"
```

#### Already Logged-In as root via Telnet



```
"root@" port:23 -login -password -name -Session
```

#### Telnet Access:



NO password required for telnet access.

```
port:23 console gateway
```

#### Polycom video-conference system no-auth shell



```
"polycom command shell"
```

#### NPort serial-to-eth / MoCA devices without password



```
nport -keyin port:23
```

#### Android Root Bridges



A tangential result of Google's sloppy fractured update approach.

```
"Android Debug Bridge" "Device" port:5555
```

#### Lantronix Serial-to-Ethernet Adapter Leaking Telnet Passwords



```
Lantronix password port:30718 -secured
```

#### Citrix Virtual Apps



```
"Citrix Applications:" port:1604
```

#### Cisco Smart Install



Vulnerable (kind of "by design," but especially when exposed).

```
"smart install client active"
```

#### PBX IP Phone Gateways



```
PBX "gateway console" -password port:23
```

#### Polycom Video Conferencing



```
http.title:"- Polycom" "Server: lighttpd"
"Polycom Command Shell" -failed port:23
```

#### Telnet Configuration:



```
"Polycom Command Shell" -failed port:23
```

#### Bomgar Help Desk Portal



```
"Server: Bomgar" "200 OK"
```

#### Intel Active Management CVE-2017-5689



```
"Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995
"Active Management Technology"
```

#### HP iLO 4 CVE-2017-12542



```
HP-ILO-4 !"HP-ILO-4/2.53" !"HP-ILO-4/2.54" !"HP-ILO-4/2.55" !"HP-ILO-4/2.60" !"HP-ILO-4/2.61" !"HP-ILO-4/2.62" !"HP-iLO-4/2.70" port:1900
```

#### Lantronix ethernet adapter’s admin interface without password



```
"Press Enter for Setup Mode port:9999"
```

#### Wifi Passwords:



Helps to find the cleartext wifi passwords in Shodan.

```
html:"def_wirelesspassword"
```

#### Misconfigured Wordpress Sites:



The wp-config.php if accessed can give out the database credentials.

```
http.html:"* The wp-config.php creation script uses this file"
```

### Outlook Web Access:



#### Exchange 2007



```
"x-owa-version" "IE=EmulateIE7" "Server: Microsoft-IIS/7.0"
```

#### Exchange 2010



```
"x-owa-version" "IE=EmulateIE7" http.favicon.hash:442749392
```

#### Exchange 2013 / 2016



```
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"
```

#### Lync / Skype for Business



```
"X-MS-Server-Fqdn"
```

### Network Attached Storage (NAS)

#### SMB (Samba) File Shares

Produces \~500,000 results...narrow down by adding "Documents" or "Videos", etc.

```
"Authentication: disabled" port:445
```

#### Specifically domain controllers:

```
"Authentication: disabled" NETLOGON SYSVOL -unix port:445
```

#### Concerning default network shares of QuickBooks files:

```
"Authentication: disabled" "Shared this folder to access QuickBooks files OverNetwork" -unix port:445
```

#### FTP Servers with Anonymous Login

```
"220" "230 Login successful." port:21
```

#### Iomega / LenovoEMC NAS Drives

```
"Set-Cookie: iomega=" -"manage/login.html" -http.title:"Log In"
```

#### Buffalo TeraStation NAS Drives

```
Redirecting sencha port:9000
```

#### Logitech Media Servers

```
"Server: Logitech Media Server" "200 OK"
```

#### Plex Media Servers

```
"X-Plex-Protocol" "200 OK" port:32400
```

#### Tautulli / PlexPy Dashboards



```
"CherryPy/5.1.0" "/home"
```

#### Home router attached USB

```
"IPC$ all storage devices"
```

### Webcams

#### D-Link webcams

```
"d-Link Internet Camera, 200 OK"
```

#### Hipcam

```
"Hipcam RealServer/V1.0"
```

#### Yawcams

```
"Server: yawcam" "Mime-Type: text/html"
```

#### webcamXP/webcam7

```
("webcam 7" OR "webcamXP") http.component:"mootools" -401
```

#### Android IP Webcam Server

```
"Server: IP Webcam Server" "200 OK"
```

#### Security DVRs

```
html:"DVR_H264 ActiveX"
```

#### Surveillance Cams:

With username:admin and password: :P

```
NETSurveillance uc-httpd
Server: uc-httpd 1.0.0
```

### Printers & Copiers:



#### HP Printers

```
"Serial Number:" "Built:" "Server: HP HTTP"
```

#### Xerox Copiers/Printer

```
ssl:"Xerox Generic Root"
```

#### Epson Printer

```
"SERVER: EPSON_Linux UPnP" "200 OK"
"Server: EPSON-HTTP" "200 OK"
```

#### Canon Printers

```
"Server: KS_HTTP" "200 OK"
"Server: CANON HTTP Server"
```

### Home Devices

#### Yamaha Stereos

```
"Server: AV_Receiver" "HTTP/1.1 406"
```

#### Apple AirPlay Receivers

Apple TVs, HomePods, etc.

```
"\x08_airplay" port:5353
```

#### Chromecasts / Smart TVs

```
"Chromecast:" port:8008
```

#### Crestron Smart Home Controllers

```
"Model: PYNG-HUB"
```

### Random Stuff

#### OctoPrint 3D Printer Controllers

```
title:"OctoPrint" -title:"Login" http.favicon.hash:1307375944
```

#### Etherium Miner

```
"ETH - Total speed"
```

#### Apache Directory Listings

Substitute .pem with any extension or a filename like phpinfo.php.

```
http.title:"Index of /" http.html:".pem"
```

#### Misconfigured WordPress

Exposed wp-config.php files containing database credentials.

```
http.html:"* The wp-config.php creation script uses this file"
```

#### Too Many Minecraft Servers

```
"Minecraft Server" "protocol 340" port:25565
```

#### Literally Everything in North Korea

```
net:175.45.176.0/22,210.52.109.0/24,77.94.35.0/24
```



***

### Finally Don’t forget OSINT tools :

* theHarvester
* BBOT
* OpenForAll
* Vita

***

***

THIS is my FIRST write-up about RECON ..

_**THANKS FOR READING !!!**_

***
