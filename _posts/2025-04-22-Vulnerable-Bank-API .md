---
title: "Vulnerable Bank API"
date: 2025-04-22
categories: [OWASP, API]
tags: [OWASP API TOP 10, BOLA, BFLA]
layout: post
publish: true
---

# HACKING A BANK API

[Ghost St Badmus](https://x.com/commando_skiipz?t=rPix1FAXa-vFamgkrxjjnQ&s=09), a cracked Snr. Application Security Engineer developed a vulnerable Web Application, API and Mobile Application for Pentesters, Bug Bounty Hunters and Security Researchers. To test their skills without messing up real world infrastructures.


In this write-up, I'll be exploiting the APIs in the web apllication version of the vulnerable bank lab, as complement and test for my recently completed course from [APISEC University](https://university.apisec.ai/)

---

**Link to these projects can be found:**

[🏦 Vulnerable Bank](https://github.com/Commando-X/vuln-bank)

[📱 Vulnerable Bank Mobile Application](https://github.com/Commando-X/vuln-bank-mobile)


The installation process of these labs are included in the documentation on github

---

## Setup
First thing we are doing is reverse engineering the API so we can work on it on Postman. Navigate to the **openapi.yaml** on the github repo, copy the JSON and paste into [swagger editor](https://editor.swagger.io)

![alt](/assets/images/vuln-api/A1.png)


![alt](/assets/images/vuln-api/A2.png)


![alt](/assets/images/vuln-api/A3.png)


- We have the swagger file imported into postman. Now, let's start hacking!

## API1:  BOLA (Broken Obeject Level Authorization)
BOLA (Broken Object Level Authorization) is a common and critical vulnerability that occurs when an API exposes object identifiers (like user IDs, account numbers, or transaction IDs) and fails to properly verify whether the currently authenticated user is authorized to access that object.



### Exploitation:
Let's start with exploiting BOLA from the API endpoint.

As usual, register 2 accounts like we are testing for IDOR. Let's call both Acount A and Account B respectively. On Postman, set your **baseurl** in the collection to **http://localhost:5000**. Login in.

![alt](/assets/images/vuln-api/A5.png)


![alt](/assets/images/vuln-api/A6.png)

To test an ID parameter or unique number, we are going to test the transfer API so we can have a transaction history on our dashboard. Log in into Account A and initiate a transfer to Account B.

![alt](/assets/images/vuln-api/A7.png)

We have new balnce since we removed **$100** 

Now, let's log in again as Account B and move to the transaction endpoint so we can view the transations of Account A.

![alt](/assets/images/vuln-api/A8.png)

- Switch the account number to that of Account A, which is **2121763565** in my case.

![alt](/assets/images/vuln-api/A9.png)

From the image above, we can notice we are able to view the transaction details of Account A while authenticated as Account B.

The API failed to enforce object-level authorization. It trusted that any user who sends a valid token could access any account's transactions, as long as they knew the account ID.

### Fix:
Always enforce user-level authorization on every API request:

- Verify the authenticated user's ID matches the target resource (e.g., user ID, account ID).

- Never rely on client-side input or assume users will only access their own data.

- Implement backend checks to ensure users can only access, modify, or delete their own resources.


## API2: Broken Authentication

Broken Authentication is one of the most dangerous vulnerabilities in web and API security. It happens when an application fails to properly verify user identity or enforce authentication controls, allowing attackers to impersonate users or access protected resources.



### Exploitation:

To exploit this, we will be authenticated as Account B and request a password reset for Account A. We got a **Invalid Reset PIN**. Meaning, the Reset password API endpoint isn't verifying if we are authorized to carry out this action.

![alt](/assets/images/vuln-api/A10.png)

Let's proxy the request through web proxy (Burp/Caido), copy the 
reset password JSON parameter. Now, let's fuzz the PIN with *wfuzz*

![alt](/assets/images/vuln-api/A11.png)

![alt](/assets/images/vuln-api/A12.png)


Using the crafted command *wfuzz -d '{"username":"ipsalmy", "reset_pin":"FUZZ", "new_password":"Reset@1"}' -H 'Content-type: application/json' -z file,/usr/share/wordlists/SecLists/Fuzzing/3-digits-000-999.txt -u http://172.19.0.3:5000/api/v2/reset-password --hc 500* we were able to reset the password of Account A.


![alt](/assets/images/vuln-api/A13.png)

- Ensure you have Seclists wordlist installed before running this fuzz

When we try logging in into account A dashboard using the previous password we set while registering, we get an error. Try the new password we added while fzzing the endpoint and we have access to account A.

![alt](/assets/images/vuln-api/A14.png)

![alt](/assets/images/vuln-api/A15.png)

![alt](/assets/images/vuln-api/A16.png)

The API endpoint didn't verify what we are able to do or not, so this enabled us to reset another user's password.
In a real scenario this would be a complete ATO - Acoount Take Over.

### Fix:
Implement a secure password reset flow with proper verification:

- Require a unique, time-bound reset token sent to the user's email.

- Only allow password reset after verifying the token.

- Never accept direct email + new password combinations without prior authentication or token verification.

- Add rate-limiting and logging to prevent brute-force attacks



## API3: (BOPLA (Broken Object Property Level Authorization)
Broken Object Property Level Authorization (BOPLA) is a lesser-known but dangerous API vulnerability where users can modify specific fields or properties of an object that they shouldn’t have access to, even if they’re allowed to access the object itself.


### Exploitation:
For this, I tried switchig the **is_admin": false** parameter from *true* to *false* but I wasn't gettting any admin privileges or seeing the admin dashboard. So, let's try another approach.

Let's register a new user(Account C) and give it admin privileges. We can do this by introudcing the **is_admin: true** into the API endpoint.

While trying this out, I almost gave up on it thinking it's not working, but I missed something out, comma (,) to separate the JSON request.

![alt](/assets/images/vuln-api/A17.png)

![alt](/assets/images/vuln-api/A18.png)

![alt](/assets/images/vuln-api/A19.png)

![alt](/assets/images/vuln-api/A20.png)


We can confirm from both the webproxy and the dashboard that Account 3 has been registered as an admin.



### Fix:
- Whitelist allowed fields server-side

- Never trust the client to send safe data even during registration.

- Ignore or explicitly reject any unauthorized fields in the payload.

- For sensitive fields (like is_admin, role, etc.), set or manage them exclusively on the server, not through user input.



## API4:  Unrestricted Resource Consumption
This vulnerability occurs when an API allows clients to consume excessive server resources (CPU, memory, bandwidth, or database queries) without any limits or throttling, leading to performance issues, service degradation, or even denial of service (DoS).


### Exploitation:
From the Broken Authentication attack we performed earlier to be successful, it means the application is not restricting requests sent to server. Requests like unsuccessful login, forgot password, rest password and the likes. 

This renders the web application vulnerable to attacks like bruteforcing, no rate limit, password spraying and race condition.

### Fix:
- Rate Limiting:
Use tools (e.g., Nginx, API Gateways) to limit requests per user/IP.

- Pagination:
Enforce limit and offset with a max cap (e.g., limit=100).

- Timeouts & Resource Caps:
Set execution timeouts and memory limits for heavy operations.

- Authentication & Throttling:
Restrict high-resource actions to authenticated users with limits.

- Monitoring:
Track resource usage and set alerts for abnormal spikes.


## API5:  BFLA (Broken Function Level Authorization)
It's a security vulnerability where an application does not properly enforce authorization checks at the function or API endpoint level. This can allow a user to access or perform actions they shouldn’t be able to, based on their role or permissions.


### Exploitation:
To exploit this, register as a regular user, locate an admin endpoint from the swagger. Send and intercept the request through web proxy and try to perform actions only an admin is authorized to do.

I tried to delete account 1 without being the admin but this vulnerable bank seems not to be vulnerable to this. I also tried to request for a loan through account A and make account B approve the loan request, but still not vulnerable to this vulnerability. 


Hol'up! Don't scroll away yet. I found something.

There's a way aroud performing BFLA on this application. We can chain the Broken Authentication vulnerability with this one.

Let's go to jwt.io and change the *is_admin* in the JWT token from **false** to **true**. Navigate to the Delete user endpoint in postman. Copy and Paste the forged jwt iinto the Authorization tab.


![alt](/assets/images/vuln-api/A21.png)

![alt](/assets/images/vuln-api/A22.png)


Add the user ID of account A into the request and send the request.

![alt](/assets/images/vuln-api/A23.png)

Boom! We've deleted account A by using account B.

+ **Bonus**: You can dig around to find and exploit more admin endpoint not properly verifying if you are admin or not, before you perform a specific action on the server

### Fix:
- Role-Based Access Control (RBAC):
Ensure proper role validation for each function or API endpoint.

- Function-Level Authorization Checks:
Explicitly verify that the authenticated user has permission to access or perform actions on specific functions.

- Principle of Least Privilege:
Limit each user's access to only the functions and data necessary for their role.

- Centralized Authorization Logic:
Implement a consistent authorization layer (middleware or service) across all endpoints for easy management.

- Audit Logs:
Log and monitor all privileged function access to detect unauthorized attempts.


## API6: Unrestricted Access to Sensitive Business Flows
Unrestricted Access to Sensitive Business Flows refers to a security vulnerability where unauthorized users can access or perform actions on critical business processes, workflows, or resources that should be restricted based on roles, permissions, or authorization levels.


### Exploitation:
Let's head over to the Register Endpoint and create a new account(calling this Account A to replace the one deleted). Remember how we added **is_admin** earlier, let's add **"balance": 1000000.0** while creating this account. 

![alt](/assets/images/vuln-api/A24.png)

Log into the newly created account and we can see we an initial balance of $ 1000000.

### Fix:
- Role-Based Access Control (RBAC):
Enforce strict role validation to ensure only authorized users can access or modify sensitive business flows.

- Input Validation:
Validate all incoming data, ensuring no sensitive fields (like balance, admin flags) are exposed or tampered with by users.

- Server-Side Control:
Handle critical actions (e.g., adding funds, changing roles) server-side. Do not allow users to modify sensitive fields directly via requests.

- Authorization Checks for Every Action:
Always check the user's role and permissions before allowing access to any sensitive business flow or functionality.

- Endpoint Protection:
Protect sensitive endpoints by requiring additional security measures, such as multi-factor authentication (MFA) or rate limiting, to prevent unauthorized access.


## API7: SSRF (Server Side Request Forgery)
SSRF (Server-Side Request Forgery) is a vulnerability where an attacker can send crafted requests from the server-side to internal or external resources that the server can access, but which should not be accessible to the attacker. This often occurs when user-supplied URLs or IP addresses are not properly validated, allowing the attacker to exploit the API's ability to send requests.

I was unable to lacate any URL endpoint fecthing resources from the internal or external server on this application.



## API8: Security Misconfiguration
Security Misconfiguration is one of the most common and critical web application vulnerabilities. It happens when security settings are not properly defined, misapplied, or left in default state, which can expose the system to unauthorized access, sensitive data leakage, or full system compromise.

Exempting the fact that this is a vulnerable lab built specifically for testing. We can see the communication is done through an insecure HTTP protocol instead of HTTPS.

Username and passwords are being proccessed and stored in plain text which can be critical for the application, if there is a successful MITM attack.
Cookies are also in predictable base64 format and they can be forged for various exploits.

Access-Control-Allow-Origin is set to allow all URLs with the  *

We can also notice the [API Swagger documenttion](http://localhost:5000/api/docs) being publicly accessible without any password protection.




### Fix:
- Disable Debug Mode in Production
Ensure debug logs and detailed error messages are turned off in live environments.

- Implement Proper CORS Policy
Avoid Access-Control-Allow-Origin: *. Allow only trusted domains.

- Remove Unused Endpoints & Features
Eliminate default, test, or dev endpoints and unused services.

- Use Secure HTTP Headers
Add headers like Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, etc.

- Set Strong Authentication & Authorization
Enforce token-based auth (e.g., JWT) and validate user roles per endpoint.

- Validate & Sanitize All Inputs
Prevent injection, path traversal, and other user-input-based attacks.

- Restrict Admin/Privileged Access
Protect admin routes and sensitive endpoints with proper auth layers.

- Keep Dependencies & Frameworks Updated
Regularly patch libraries, packages, and server software.

- Limit Request Sizes & Rate Limit
Avoid abuse or DoS by limiting payload sizes and applying rate-limiting.

- Log & Monitor Security Events
Keep track of suspicious behavior or misused endpoints.



## API9: Improper Inventory Management
This refers to poor visibility, control, and documentation of your APIs, which increases the attack surface and makes security testing harder.
This leads to exposed or forgotten endpoints (like old versions or dev/test APIs), which attackers can find and exploit.

### Exploitation:
Move to the forgot password endpoint and request for a password reset for a victim's account. Let's do this for account A

![alt](/assets/images/vuln-api/A25.png)

Since email is not provided while registration we can't get the reset PIN for this user. In a real case, the PIN would be sent to the victim. There's a catch here. We can view the reset PIN by changing the API version from **v1** to **v2**.

![alt](/assets/images/vuln-api/A26.png)

![alt](/assets/images/vuln-api/A27.png)

We are able to view the reset pin for this user and also reset the password using the PIN

![alt](/assets/images/vuln-api/A28.png)

+ There are still more endpoints in this app you can exploit this way. Dig and find.

### Fix:
- Maintain an API Inventory
Track all public, private, internal, and third-party APIs.

- Use an API Gateway
Route all API traffic through a central gateway to monitor and control access.

- Implement API Versioning Policies
Clearly mark deprecated APIs and retire them when obsolete.

- Scan for Shadow/Unknown APIs
Regularly scan your network for undocumented or forgotten APIs.

- Restrict Non-Production Environments
Block access to staging/dev APIs from the public internet.

- Apply Consistent Naming & Documentation
Follow naming conventions and document all endpoints properly.

- Tag APIs with Metadata
Include ownership, version, environment (prod/dev), and purpose.

- Monitor & Log API Activity
Set up logging to detect usage of outdated or unknown endpoints.

# API10: Unsafe Consumption of APIs
Unsafe Consumption of APIs refers to the practice of trusting and directly using data or services from external or third-party APIs without proper validation, sanitization, or security measures. This can lead to various security issues, such as the introduction of malicious payloads, unexpected data, or exploitation of vulnerabilities in external services.


### Exploitation:
Since this app is not using any third party API, let's go with exploiting SQL injection using Postman.

Move to postman and set an environmental variable in your envirnoment. Name  the environment and the variable/parameter whatever you want. Set a payload in the value e.g we are using **'OR 1=1 --** as test.

Head over to the login API and right beside the input field for the name add **{{SQL-test}}** (whatever name you saved your environmental variable to).

![alt](/assets/images/vuln-api/A29.png)

Send the request and we are logged in as admin

![alt](/assets/images/vuln-api/A30.png)

This can be done from the webpage login form also, or you can copy and use the admin JWT token for aany attack that requires admin privileges.


+ We can also add endpoints you want to test into a collection and test them all at once, using the set variable with various payloads based on vullnerability type.


+ **Bonus**: You can test for XSS to steal user cookies in payment description. You can also test for file upload.

### Fix:
- Validate All Incoming Data
Ensure that any data received from external APIs is validated against expected schemas, types, and formats.

- Use API Security Best Practices
Secure API communication with HTTPS, and implement authentication/authorization (e.g., OAuth, API keys) to verify the API’s authenticity.

- Sanitize Data
Sanitize any input data, especially when interacting with APIs that could be prone to injection attacks or data manipulation.

- Implement Strict Error Handling
Prevent the application from revealing sensitive internal details by implementing fail-safe mechanisms and proper error logging.

- Apply Rate Limiting and Throttling
Protect your API consumption from denial-of-service (DoS) attacks by limiting the number of API requests or responses.

- Check for API Version Compatibility
 Regularly verify and ensure the consumed API version is up to date and supported. Avoid using deprecated or outdated API versions.

- Implement Timeouts and Retry Logic
Avoid indefinite waiting and system hangs by setting timeout limits for API requests and having retry logic for failed calls.

- Monitor and Audit API Responses
Continuously monitor the responses for anomalies and log interactions to track malicious behavior or unexpected data.

---


## 🧩 Wrapping Up: The Bug Stops Here… For Now 😉

Well folks, that’s a solid tour of some juicy API vulnerabilities, from Broken Authentication to BOPLA, BOLA, SSRF, and our lovable chaos agent.Security Misconfiguration. We poked around, nudged a few doors open (ethically, of course), and saw firsthand how simple mistakes can turn into serious security gaps.

But here's the kicker, I didn’t even exploit everything this lab had to offer. That’s right, there are more hidden treasures (or ticking time bombs, depending on your perspective) waiting to be found. If you’ve got the curiosity and caffeine, I encourage you to keep digging.

Security is a journey, not a destination, and sometimes that journey involves a lot of curl, wfuzz, and “Wait… did I just reset someone else’s password!?

So go ahead, fire up your tools, launch your browser proxy, and explore responsibly. Just remember; always test within ethical scope or the only thing you’ll be hacking is your future job prospects 😅.

Until next time, stay sharp, stay ethical, and don’t forget to fix your CORS headers.

Happy Hacking ✌️ 🔥 

~[iPsalmy](https://x.com/Dghost_Ninja?t=Tu9xP2NeeGKuznrbgdQizQ&s=09)
