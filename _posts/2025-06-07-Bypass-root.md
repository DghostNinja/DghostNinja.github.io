---
title: "Bypassing Root & Emulator Detection in Mobile Apps"
date: 2025-06-07
categories: [MobileSecurity]
tags: [MAPT, Security-Bypass, Security Research, Frida, Objection, Genymotion]
layout: post
publish: true
---

# Introduction
🧰 Tools: Frida, apk-mitm, Objection, Genymotion  
📱 Target App: (Redacted)

Mobile app developers often implement root/jailbreak and emulator detection to protect sensitive data, prevent tampering, or block automation. But like any client-side control, these mechanisms can be bypassed with the right knowledge and tools.

In this post, I’ll walk you through how I defeated both root and emulator detection mechanisms in a real-world Android application. I’ll cover how I bypassed the detection logic, the technical steps I took to disable it and also the rabbit holes I fell into. Whether you're a security researcher, reverse engineer, or just curious about mobile app internals, this post will give you a hands-on look at how these defenses work and how to get around them.

## Dive
![alt](/assets/images/Root-detection/A1.jpg) 

Recently got faced with this challenging task. It was challenging because that was my first time facing such issue on a a live mobile application pentest.

### **The Rabbit hole**

First thing I thought of was using objection to patch and repack the mobile application to remove the security feature, because I have once done this before. Didnt work this time.
I later decided to go with using objection to explore the app and I kept on running into some bunch of errors.

So, I decdided to patch the app using [apk-mitm](https://github.com/niklashigi/apk-mitm). This CLI tool helps to modifiy the source code to disable the security checks and replace some network configuration files, but this didn't work also.


![alt](/assets/images/Root-detection/A5.jpg) 

I then moved to using frida and hooking the app with a bypass script.


## The Solution
I generated a first [js code](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Fbypass-root-emulator.js) to hook the mobile app with.

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

![alt](/assets/images/Root-detection/A2.jpg) 


This script was only able to bypass the emulator check, but not root detection. This gave me the confidence to keep digging, since I got a step closer to my main goal.

I generated [a second](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Fbypass-root-%26-emulator-detection.js#L1-L117).

This Frida script is designed to  bypass security checks in Android apps that try to detect if the device is rooted, running in an emulator, or being debugged. Can be used in reverse engineering, pen-testing, or modifying app behavior.

It does this by faking device information to look like a real Samsung phone. 

- Hiding debugger presence by always returning false for debugger checks.
- Hiding root binaries (su, magisk, busybox, etc.) from file existence checks. 
- Faking system properties (like ro.debuggable) to values typical of non-rooted, production devices.
- Blocking execution of suspicious root-related commands via Runtime.exec and ProcessBuilder. 
- Preventing detection of the su process by intercepting file reads to /proc/*/cmdline.


![alt](/assets/images/Root-detection/A3.jpg) 

After hooking the script to the app with frida, voilà! I was able to get pass both the root and emulator check.

```
I can't show the bypassed mobile app screenshot for ethical and legal reasons.
```

### **What Didn’t Work**

    Patching via Objection failed due to runtime checks

    apk-mitm patched the app but did not disable checks effectively

    App likely used delayed root verification after login flow

    Some checks were only triggered during specific screens or user actions

### **From the Developer’s POV**

Root and emulator checks are common in:

    Banking apps to prevent credential leaks

    Fintech apps to meet PCI/GDPR compliance

    Streaming apps to prevent automation or pirating

They sometimes use Google’s SafetyNet or Play Integrity APIs, which can’t be bypassed this easily. Luckily, this app was not using those.

## Final thought 
At some point I wanted to give up. I knew persistence would win. Security research isn’t always a straight path. You try, fail, pivot and eventually, something clicks. I had to think like an attacker. They won't stop till they find a way to bypass any security check. Plus, what's the purpose of me being in love wih Security research, if I can't even do the research. 

I also had a plan to go the smali route where I'd have to manually remove detection logic in .smali files (e.g., strings like /system/xbin/su, getprop ro.debuggable) and rebuild the APK. Luckily, I didn’t need to go that far this time. The first method just worked.

```
💡 Pro Tip: You can make use of Magisk/MagiskHide with a proper DenyList for most basic root checks. 

> Some apps use System.loadLibrary() with native C++ checks, watch out

> Try Xposed modules like LSPosed for stubborn detection logic

> Always test your scripts on both real and emulated    environments

> Look out for TracerPid and delayed root detection via postDelayed
```

# Bonus
I created a small bash script to help automate pushing the correct frida-server to the emulator and setting permissions. Super helpful when you're in a hurry or doing repeated tests. Grab it [here](https://github.com/DghostNinja/Application-Security/blob/main/APPSEC-notes%2FMobSec%2Ffrida_set.sh) and grant permission and run. 
 
All you have to do is download the right frida server for your andriod emulator from [Github](https://github.com/frida/frida/releases/tag/17.1.2), rename to **frida-server** and run the script.



![alt](/assets/images/Root-detection/A4.jpg) 

Remember to stay Ethical and keep researching. See you in the next write-up.

Happy hacking!✌️