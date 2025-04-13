---
title: "Cryptographic Failures - BreakTheFlask"
date: 2025-04-12
categories: [OWASP, Code review, BreakTheFlask]
tags: [Code review, IDOR, BAC]
layout: post
publish: true
---

# Cryptographic Failure Vulnerability


Welcome to the Crypto Failures Lab — a playground intentionally riddled with practical, real-world cryptographic vulnerabilities. If you're a seasoned security researcher or an aspiring bug bounty hunter, this walk-through is designed to take you step-by-step through each vulnerability, showing both how to exploit them and how to patch them.

Let's dive right in *[LAB ==> **https://github.com/DghostNinja/BreakTheFlask.git**]*

```python
from flask import Flask, request, jsonify, make_response, redirect, send_file
import jwt
import hashlib
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)

FLAG = "flag{this_is_the_super_secret_flag}"
ADMIN_FLAG = "flag{admin_access_granted_super_privileges}"

JWT_SECRET = "supersecret"
ENCRYPTION_KEY = b"ThisIsA16ByteKey"

def encrypt_ecb(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    padded = pad(data.encode(), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def decrypt_ecb(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    decoded = base64.b64decode(data)
    decrypted = unpad(cipher.decrypt(decoded), 16)
    return decrypted.decode()

@app.route("/")
def index():
    return """<h2>Crypto Failures Lab - BreakTheFlask </h2><ul>
        <li><a href='/login'>/login</a> - Get a token</li>
        <li><a href='/store_secret'>/store_secret</a> - Encrypt your secret</li>
        <li><a href='/view_secret?data=...'>/view_secret</a> - Decrypt secret (Guess the key!)</li>
        <li><a href='/reset_password?email=test@example.com'>/reset_password</a> - Guess the reset token</li>
        <li><a href='/log?secret=1234'>/log</a> - Log your secret</li>
        <li><a href='/auth_required'>/auth_required</a> - Authenticate using your token</li>
        <li><a href='/download/flag.txt?token=...'>/download/flag.txt</a> - Download the flag (if you have the token!)</li>
        <li><a href='/cookie_test'>/cookie_test</a> - Steal a session cookie</li>
        <li><a href='/admin_panel'>/admin_panel</a> - Admin-only area</li>
    </ul>
    <p>Can you find the flag? Good luck!</p>"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        role = "admin" if username.lower() == "admin" else "user"
        payload = {"user": username, "role": role}
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return '''<form method="post">
        Username: <input name="username"><br>
        <button type="submit">Login</button></form>'''

@app.route("/auth_required")
def auth_required():
    token = request.headers.get("Authorization")
    if not token:
        return "Missing token", 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return f"Welcome {decoded['user']}!"
    except Exception as e:
        return f"Invalid token: {str(e)}", 403

@app.route("/admin_panel")
def admin_panel():
    token = request.headers.get("Authorization")
    if not token:
        return "Token required", 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if decoded.get("role") == "admin":
            return f"<h2>Admin Panel</h2><p>Welcome, {decoded['user']}!</p><p>Here's your special flag: <b>{ADMIN_FLAG}</b></p>"
        else:
            return "Access denied: not an admin", 403
    except Exception as e:
        return f"Invalid token: {str(e)}", 403

@app.route("/store_secret", methods=["GET", "POST"])
def store_secret():
    if request.method == "POST":
        secret = request.form.get("secret")
        encrypted = encrypt_ecb(secret)
        return f"Encrypted (ECB) secret: {encrypted}"
    return '''<form method="post">
        Secret: <input name="secret"><br>
        <button type="submit">Encrypt</button></form>'''

@app.route("/view_secret")
def view_secret():
    encrypted = request.args.get("data")
    try:
        decrypted = decrypt_ecb(encrypted)
        return f"Decrypted: {decrypted}"
    except:
        return "Failed to decrypt."

@app.route("/reset_password")
def reset_password():
    email = request.args.get("email")
    if not email:
        return "Missing email"
    token = hashlib.md5((email + str(int(time.time() / 60))).encode()).hexdigest()
    return f"Reset link: /reset_form?token={token}"

@app.route("/log")
def log():
    secret = request.args.get("secret", "")
    encoded = base64.b64encode(secret.encode()).decode()
    print(f"[!] Logged: {encoded}")
    return "Secret logged."

@app.route("/cookie_test")
def cookie_test():
    token = jwt.encode({"user": "admin", "role": "admin"}, JWT_SECRET, algorithm="HS256")
    resp = make_response("Cookie set for admin")
    resp.set_cookie("auth_token", token, httponly=False, secure=False)
    return resp

@app.route("/download/<filename>")
def download(filename):
    token = request.args.get("token")
    if token != "letmein":
        return "Invalid download token", 403
    if filename == "flag.txt" and token == "letmein":
        return FLAG
    return f"Simulated secure download: {filename}"

@app.route("/oracle", methods=["POST"])
def oracle():
    data = request.json.get("data")
    try:
        decrypted = decrypt_ecb(data)
        return jsonify({"padding": "valid"})
    except Exception:
        return jsonify({"padding": "invalid"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

## 1. AES-ECB Mode Encryption

Overview

The app uses AES in ECB (Electronic Code Book) mode. This mode is deterministic and leaks patterns, making it weak and vulnerable.

### Vulnerable code :
```python
def encrypt_ecb(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    padded = pad(data.encode(), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()
```

This part of the code is vulnerable to **Block Alignment Attack** because ECB encrypts identical blocks to identical ciphertext, you can spot the change block and infer information. 

This can be exploited manuanly by navigating to the **/store_secret**, submit a text sample like **AAAAAAAAAAAAAAAAadmin** and note the ciphertext.
Submit another like **AAAAAAAAAAAAAAAAguest** and compare.

Observe reused blocks in base64.

![text A](/assets/images/B7.png)

![text B](/assets/images/B8.png)

Both are base64 representations of AES-ECB encrypted data. At a glance, you can visually spot the pattern reuse:

    The first several characters (MPfvFUzbYCaQ1W2MxL/gB) are identical in both.

AES-ECB mode leaks patterns. Identical plaintext blocks always result in identical ciphertext blocks.

This allows block-level inference, especially with known prefixes or repeating inputs.

### Fix:
Switch to a secure mode like CBC with IV:
```python
iv = get_random_bytes(16)
cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
```

---
#### Shout-out to my guy for attempting this challenge. Check out his own break down on X ==> [Kwesi Larry](https://x.com/okxwizard/status/1911297162081661309?t=q7Z1La_gvAjS30GEgmVCXg&s=19)