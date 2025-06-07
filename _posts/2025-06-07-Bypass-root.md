---
title: "Bypassing Root & Emulator Detection in Mobile Apps"
date: 2025-06-07
categories: [MobileSecurity]
tags: [MAPT, Security-Bypass, Secueity Research]
layout: post
publish: false
---

# > Introduction

Mobile app developers often implement root/jailbreak and emulator detection to protect sensitive data, prevent tampering, or block automation. But like any client-side control, these mechanisms can be bypassed with the right knowledge and tools.

In this post, I’ll walk you through how I defeated both root and emulator detection mechanisms in a real-world Android application. I’ll cover how I bypassed the detection logic, the technical steps I took to disable it and also the rabbit holes I fell into. Whether you're a security researcher, reverse engineer, or just curious about mobile app internals, this post will give you a hands-on look at how these defenses work and how to get around them.

## The Dive

![alt](/assets/images/Root-detection/A1.png)


## The Solution
I first generated a [js code](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Fbypass-root-emulator.js) to hook with frida and the mobile app. 
[]


This script was able bypass the root detection, which gave me the confidence to keep digging since I got a step closer to my main goal.



# Bonus
I made a bash script to automate the process of installing and pushing the frida server into your andruod emulator easily. Figured out the manual process can sometimes be a little time taking, if one is running on schedule. 

All you have to do is download the right frida server for your andriod emulator from [Github](https://github.com/frida/frida/releases/tag/17.1.2)

Link to the frida server setup can be found [here](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Ffrida_set.sh). All you have to do is grant permmission and run. 

See you in the next write-up. Happy hacking!✌️