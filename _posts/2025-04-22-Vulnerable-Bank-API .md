---
title: "Vulnerable Bank API"
date: 2025-04-22
categories: [OWASP, API]
tags: [OWASP API TOP 10, BOLA, BFLA]
layout: post
publish: true
---

[Ghost St Badmus](https://x.com/commando_skiipz?t=rPix1FAXa-vFamgkrxjjnQ&s=09), a cracked Snr. Application Security Engineer, developed a vulnerable Web Application, API and Mobile Application for Pentesters, Bug Bounty Hunters and Security Researchers. To test their skills without messing up real world infrastructures.

---
**Link to this projects can be found:**

[Vulnerable Bank](https://github.com/Commando-X/vuln-bank)

[📱 Vulnerable Bank Mobile Application]()


The installation process of these labs are included in the documentation on github
---

# HACKING API

In this write-up, I'll be exploiting the APIs in the web apllication version of the vulnerable lab, as a complement to my completed course from [APISEC University](https://university.apisec.ai/)

## Setup
First thing we are doing is reverse engineering the API so we can work on it on Postman. Navigate to the **openapi.yaml** on the github repo, copy the JSON and paste into [swagger editor](https://editor.swagger.io)

![alt](/assets/images/vuln-api/A1.png)


![alt](/assets/images/vuln-api/A2.png)


![alt](/assets/images/vuln-api/A3.png)


- We have the swagger file imported into postman. Now, let's start hacking!


