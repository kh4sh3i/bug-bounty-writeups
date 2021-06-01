# bug bounty writeups
A list of available Bug Bounty &amp; Disclosure Programs and Write-ups.

# Table of Contents
* [Cross Site Scripting (XSS)](#cross-site-scripting-xss)
* [Cross Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
* [Clickjacking (UI Redressing Attack)](#clickjacking-ui-redressing-attack)
* [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
* [Subdomain Takeover](#subdomain-takeover)
* [Denial of Service (DOS)](#denial-of-service-dos)
* [Authentication Bypass](#authentication-bypass)
* [SQL injection](#sql-injection)
* [Insecure Direct Object Reference (IDOR)](#insecure-direct-object-reference-idor)
* [2FA bypass](#2fa-bypass)
* [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
* [Race Condition](#race-condition)
* [Remote Code Execution (RCE)](#remote-code-execution-rce)
* [External XML Entity Attack (XXE)](#external-xml-entity-attack-xxe)
* [Insecure Deserialization](#insecure-deserialization)
* [Business Logic Flaw](#business-logic-flaw)
* [HTTP Header Injection](#http-header-injection)
* [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
* [Broken link hijacking (BLH)](#broken-link-hijacking-blh)
* [DOM-based vulnerabilities](#dom-based-vulnerabilities)
* [Cross-origin resource sharing (CORS)](#cross-origin-resource-sharing-cors)
* [HTTP request smuggling](#http-request-smuggling)
* [OS command injection](#os-command-injection)
* [Directory traversal](#directory-traversal)
* [WebSockets Attack](#websockets-attack)
* [Web cache poisoning](#web-cache-poisoning)
* [Information disclosure](#information-disclosure)
* [CRLF injection](#crlf-injection)
  

### Cross Site Scripting (XSS)

### Cross Site Request Forgery (CSRF)

### Clickjacking (UI Redressing Attack)

### Local File Inclusion (LFI)

### Subdomain Takeover

### Denial of Service (DOS)

### Authentication Bypass

### SQL injection

* [Fun sql injection — mod_security bypass](https://infosecwriteups.com/fun-sql-injection-mod-security-bypass-644b54b0c445)
* [How I Found Sql Injection on 8x8 , Cengage,Comodo,Automattic,20 company](https://ahmadaabdulla.medium.com/how-i-found-sql-injection-on-8x8-cengage-comodo-automattic-20-company-c296d1a09f63)
* [Admin Panel Accessed Via SQL Injection…](https://medium.com/@ratnadip1998/admin-panel-accessed-via-sql-injection-ezy-boooom-57dc60c2815f)
* [Sql Injection via hidden parameter](https://hajarerutik9.medium.com/sql-injection-via-hidden-parameter-6da7699248fc)
* [Time Based Blind SQL Injection](https://marxchryz.medium.com/my-bug-bounty-journey-and-my-first-critical-bug-time-based-blind-sql-injection-aa91d8276e41)
* [How i got easy $$$ for SQL Injection Bug](https://rafipiun.medium.com/how-i-got-easy-for-sql-injection-bug-7ff622236e4c)
* [Turning Blind Error Based SQL Injection into Exploitable Boolean One](https://ozguralp.medium.com/turning-blind-error-based-sql-injection-into-an-exploitable-boolean-one-85d6be3ca23b)
* [SQL Injection & Remote Code Execution - Double P1](https://shahjerry33.medium.com/sql-injection-remote-code-execution-double-p1-6038ca88a2ec)
* [double qoute injection](https://medium.com/sud0root/bug-bounty-writeups-exploiting-sql-injection-vulnerability-20b019553716)
* [Akamai Web Application Firewall Bypass Journey: Exploiting “Google BigQuery” SQL Injection Vulnerability](https://hackemall.live/index.php/2020/03/31/akamai-web-application-firewall-bypass-journey-exploiting-google-bigquery-sql-injection-vulnerability/)
* [Blind (time-based) SQLi - Bug Bounty](https://jspin.re/fileupload-blind-sqli/)
* [SQL injection through User-Agent](https://medium.com/@frostnull/sql-injection-through-user-agent-44a1150f6888)
* [Comma is forbidden! No worries!! Inject in insert/update queries without it](https://blog.redforce.io/sql-injection-in-insert-update-query-without-comma/)


### Insecure Direct Object Reference (IDOR)

* [How I made it to Google HOF?](https://infosecwriteups.com/how-i-made-it-to-google-hof-f1cec85fdb1b)
* [An Interesting Account Takeover!!](https://mayank-01.medium.com/an-interesting-account-takeover-3a33f42d609d)
* [IDOR Vulenebility with empty response still exposing sensitive details of customers!](https://rahulvarale.medium.com/idor-vulenebility-with-empty-response-still-exposing-sensitive-details-of-customers-bdce0a6a1b07)
* [Exploiting CORS to perform an IDOR Attack leading to PII Information Disclosure](https://notmarshmllow.medium.com/exploiting-cors-to-perform-an-idor-attack-leading-to-pii-information-disclosure-95ef21ecf8ee)
* [Story of a very lethal IDOR.](https://infosecwriteups.com/idor-that-allowed-me-to-takeover-any-users-account-129e55871d8)
* [Full account takeover worth $1000 Think out of the box](https://mokhansec.medium.com/full-account-takeover-worth-1000-think-out-of-the-box-808f0bdd8ac7)
* [IDOR via Websockets allow me to takeover any users account](https://mokhansec.medium.com/idor-via-websockets-allow-me-to-takeover-any-users-account-23460dacdeab)
* [An Interesting Account Takeover Vulnerability](https://avanishpathak46.medium.com/an-interesting-account-takeover-vulnerability-a1fbec0e01a)
* [The YouTube bug that allowed unlisted uploads to any channel](https://infosecwriteups.com/the-youtube-bug-that-allowed-uploads-to-any-channel-3b41c7b7902a)
* [My first bug on Google](https://infosecwriteups.com/my-first-bug-on-google-observation-wins-1a13d0ea54b0)
* [Accidental Observation to Critical IDOR](https://infosecwriteups.com/accidental-observation-to-critical-idor-d4d910a855bf)


### 2FA bypass

* [How I Might Have Hacked Any Microsoft Account](https://thezerohack.com/how-i-might-have-hacked-any-microsoft-account)
* [Is Math.random() Safe? from missing rate limit to bypass 2fa and possible sqli](https://neroli.medium.com/is-math-random-safe-from-missing-rate-limit-to-bypass-2fa-and-possible-sqli-2a4ea66f82c5)
* [Cracking the 2FA](https://medium.com/@rushikesh12gaikwad/cracking-the-2fa-215d24ccb29b)
* [How I bypassed 2fa in a 3 years old private program!](https://shivangx01b.github.io/2fa_bypass/)
* [Bypass 2FA like a Boss](https://infosecwriteups.com/bypass-2fa-like-a-boss-378787707ba)
* [Two Factor Authentication Bypass $5](https://aungpyaekoko.medium.com/two-factor-authentication-bypass-50-5b397e68cfed)
* [2 FA Bypass via CSRF Attack](https://vbharad.medium.com/2-fa-bypass-via-csrf-attack-8f2f6a6e3871)
* [How to bypass a 2FA with a HTTP header](https://medium.com/@YumiSec/how-to-bypass-a-2fa-with-a-http-header-ce82f7927893)
* [Bypass HackerOne 2FA requirement and reporter blacklist](https://medium.com/japzdivino/bypass-hackerone-2fa-requirement-and-reporter-blacklist-46d7959f1ee5)
* [2FA Bypass via Forced Browsing](https://infosecwriteups.com/2fa-bypass-via-forced-browsing-9e511dfdb8df)


### Server Side Request Forgery (SSRF)

### Race Condition

### Remote Code Execution (RCE)

### External XML Entity Attack (XXE)

### Insecure Deserialization

* [How i found a 1500$ worth Deserialization vulnerability](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
* [Remote code execution through unsafe unserialize in PHP](https://www.sjoerdlangkemper.nl/2021/04/04/remote-code-execution-through-unsafe-unserialize/)

### Business Logic Flaw

### HTTP Header Injection

### Server-Side Template Injection (SSTI)

### Broken link hijacking (BLH)

### DOM-based vulnerabilities

### Cross-origin resource sharing (CORS)

### HTTP request smuggling

### OS command injection

### Directory traversal

### WebSockets Attack

### Web cache poisoning

* [Breaking GitHub Private Pages for $35k](https://robertchen.cc/blog/2021/04/03/github-pages-xss)
* [Automate Cache Poisoning Vulnerability - Nuclei](https://blog.melbadry9.xyz/fuzzing/nuclei-cache-poisoning)
* [Poisoning your Cache for 1000$ - Approach to Exploitation Walkthrough](https://galnagli.com/Cache_Poisoning/)
* [Cache Poisoning DoS](https://iustin24.github.io/Cache-Key-Normalization-Denial-of-Service/)
* [EN | Account Takeover via Web Cache Poisoning based Reflected XSS](https://lutfumertceylan.com.tr/posts/acc-takeover-web-cache-xss/)
* [Chaining Cache Poisoning To Stored XSS](https://medium.com/@nahoragg/chaining-cache-poisoning-to-stored-xss-b910076bda4f)

### Information disclosure

### CRLF injection



### Made By
kh4sh3i


### License
 CC0-1.0 License
