---
title: "Bypassing Root & Emulator Detection in Mobile Apps"
date: 2025-06-07
categories: [MobileSecurity]
tags: [MAPT, Security-Bypass, Secueity Research, Frida, Objection, Genymotion]
layout: post
publish: true
---

# Introduction
🧰 Tools: Frida, apk-mitm, Objection, Genymotion  
📱 Target App: (Redacted)

Mobile app developers often implement root/jailbreak and emulator detection to protect sensitive data, prevent tampering, or block automation. But like any client-side control, these mechanisms can be bypassed with the right knowledge and tools.

In this post, I’ll walk you through how I defeated both root and emulator detection mechanisms in a real-world Android application. I’ll cover how I bypassed the detection logic, the technical steps I took to disable it and also the rabbit holes I fell into. Whether you're a security researcher, reverse engineer, or just curious about mobile app internals, this post will give you a hands-on look at how these defenses work and how to get around them.

## The Dive
> (/assets/images/Root-detection/A1.png) the error we are dealing

Recently got faced with this challenging task. It was challenging because that was my first time facing such issue on a a live mobile application.

####
The Rabbit hole

First thing I thought of was using objection to p
atch and repack the mobile application to remove the security feature, because I have once done this before. Didnt work this time.
I later decided to go with using objection to explore the app and I kept on running into some bunch of errors

So, I decdided to patch the app using [apk-mitm](https://github.com/niklashigi/apk-mitm). This CLI tool would have modified the source to disable the security checks and replace some network configuration files, but this didn't work.

[]apk-mitm image 






## The Solution
I generated a first [js code](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Fbypass-root-emulator.js) to hook with frida and the mobile app. 

```js
Java.perform(function () {
    var Build = Java.use("android.os.Build");
    var Debug = Java.use("android.os.Debug");

    // Bypass "Build.FINGERPRINT" and related emulator checks
    Build.FINGERPRINT.value = "samsung/SM-G975F";
    Build.MODEL.value = "SM-G975F";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.DEVICE.value = "beyond1";
    Build.PRODUCT.value = "beyond1";

    // Bypass Debug checks
    Debug.isDebuggerConnected.implementation = function () {
        return false;
    };

    // Optional: Bypass common root file checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var name = this.getAbsolutePath();
        if (
            name.indexOf("su") !== -1 ||
            name.indexOf("busybox") !== -1 ||
            name.indexOf("magisk") !== -1
        ) {
            return false;
        }
        return this.exists();
    };

    console.log("[+] Root and emulator checks bypassed.");
});
```

[]image of root bypass but not emulator


This script was only able to bypass the root detection, but not tye emulator. This gave me the confidence to keep digging, since I got a step closer to my main goal.

I generated [a second](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Fbypass-root-%26-emulator-detection.js#L1-L117).

This Frida script is designed to  bypass security checks in Android apps that try to detect if the device is rooted, running in an emulator, or being debugged. Can be used in reverse engineering, pen-testing, or modifying app behavior.

> It does this by faking device information to look like a real Samsung phone. Hiding debugger presence by always returning false for debugger checks. Hiding root binaries (su, magisk, busybox, etc.) from file existence checks. Faking system properties (like ro.debuggable) to values typical of non-rooted, production devices.Blocking execution of suspicious root-related commands via Runtime.exec and ProcessBuilder. Preventing detection of the su process by intercepting file reads to /proc/*/cmdline.


After hooking the script to the app with frida, voilà! I was able to get pass both the root and emulator check.

[]image of both being succesful

## Final thought 
> At some point I wanted to give up but I had to think like an attacker. They won't stop till they find a way to bypass any security check. Plus, what's the purpose of me being in love wih Security research if I can't even do the research. 

> I also add another abother idea of manually removing the security check from the smali and repacking the app. The first method just worked at the end so I didn't need to do this.


> 💡 **Pro Tip**: You can make use of Magisk/MagiskHide with a proper DenyList for most basic root checks.

# Bonus
I made a bash script to automate the process of installing and pushing the frida server into your andruod emulator easily. Figured out the manual process can sometimes be a little time taking, if one is running on schedule. 

All you have to do is download the right frida server for your andriod emulator from [Github](https://github.com/frida/frida/releases/tag/17.1.2)

Link to the frida server setup can be found [here](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Ffrida_set.sh). All you have to do is grant permmission and run. 


See you in the next write-up. Happy hacking!✌️