---
title: "Insecure Design - BreakTheFlask"
date: 2025-05-30
categories: [OWASP, Code review, BreakTheFlask]
tags: [Code review, IDOR, BAC]
layout: post
publish: true
---


# Explaining and Insecure Design
Hello Hacker! Welcome to another BreakTheFlask Session. This should be the last vulnerable code for this specific session.

Today, we will be exploiting and explaining the vulnerabilities caused by Insecure design in this code today.

Using the vulnerable flask code from ==> **https://github.com/DghostNinja/BreakTheFlask.git**

```python
from flask import Flask, request, session, redirect, render_template_string, jsonify
import threading
import time
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vaultapp-insecure-secret'

# === DATABASE SETUP ===
DB = 'vaultapp.db'

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        balance INTEGER DEFAULT 1000,
        reset_code TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'adminpass')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('player', 'playerpass')")
    conn.commit()
    conn.close()

init_db()

# === ROUTES ===

@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return render_template_string('''
        <h2>VaultApp Login</h2>
        <form method="POST" action="/login">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <p><a href="/reset">Forgot Password?</a></p>
    ''')

@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    pw = request.form['password']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pw))
    row = c.fetchone()
    conn.close()
    if row:
        session['user'] = user
        return redirect('/dashboard')
    return "Invalid login", 403

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE username=?", (user,))
    balance = c.fetchone()[0]
    conn.close()
    return render_template_string(f'''
        <h2>Welcome {user}</h2>
        <p>Your balance: ${balance}</p>
        <form method="POST" action="/transfer">
            Send $ to: <input name="to"><br>
            Amount: <input name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
        <p><a href="/logout">Logout</a></p>
    ''')

# === VULNERABLE BUSINESS LOGIC ===
@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user' not in session:
        return redirect('/')
    sender = session['user']
    recipient = request.form['to']
    amount = int(request.form['amount'])

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # INSECURE DESIGN: No server-side limit enforcement
    c.execute("SELECT balance FROM users WHERE username=?", (sender,))
    sender_balance = c.fetchone()
    if not sender_balance:
        return "Invalid sender", 403
    if sender_balance[0] < amount:
        return "Insufficient funds", 403

    # RACE CONDITION: No transaction locking
    c.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, sender))
    c.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, recipient))
    conn.commit()
    conn.close()

    return f"Transferred ${amount} to {recipient}!"

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'GET':
        return render_template_string('''
            <h2>Password Reset</h2>
            <form method="POST">
                Username: <input name="username"><br>
                <input type="submit" value="Request Reset Code">
            </form>
        ''')
    else:
        user = request.form['username']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        code = os.urandom(4).hex()
        # MISUSED FLOW: No email validation, reset code set directly
        c.execute("UPDATE users SET reset_code=? WHERE username=?", (code, user))
        conn.commit()
        conn.close()
        return f"Reset code for {user}: {code}<br><a href='/reset_confirm'>Continue</a>"

@app.route('/reset_confirm', methods=['GET', 'POST'])
def reset_confirm():
    if request.method == 'GET':
        return render_template_string('''
            <h2>Confirm Reset</h2>
            <form method="POST">
                Username: <input name="username"><br>
                Code: <input name="code"><br>
                New Password: <input name="newpw"><br>
                <input type="submit" value="Reset Password">
            </form>
        ''')
    else:
        user = request.form['username']
        code = request.form['code']
        newpw = request.form['newpw']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT reset_code FROM users WHERE username=?", (user,))
        dbcode = c.fetchone()
        if dbcode and dbcode[0] == code:
            c.execute("UPDATE users SET password=?, reset_code=NULL WHERE username=?", (newpw, user))
            conn.commit()
            conn.close()
            return "Password reset! <a href='/'>Login</a>"
        conn.close()
        return "Invalid reset code", 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# === RACE CONDITION EXPLOIT ENDPOINT FOR TESTING ===
@app.route('/race_test')
def race_test():
    if 'user' not in session:
        return "Not logged in", 403
    def do_transfer():
        with app.test_client() as c:
            c.set_cookie("localhost", "session", request.cookies.get("session"))
            c.post('/transfer', data={'to': 'admin', 'amount': '100'})

    threads = [threading.Thread(target=do_transfer) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    return "Race test completed."

# === DEBUGGING / INFO ===
@app.route('/dump')
def dump():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username, balance FROM users")
    data = c.fetchall()
    conn.close()
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
```

From the insecure design vulnerable code above, we can find:

## 1. Business Logic Flaw – No Transfer Limits
Overview

This is a vulnerability that arise when an application’s intended workflow can be manipulated in unintended ways. They don’t exploit code weaknesses directly, they exploit flaws in design, assumptions, and logic behind how the application behaves.


### Vulnerable Code:
```python
@app.route('/transfer', methods=['POST'])
def transfer():
    ...
    amount = int(request.form['amount'])

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # INSECURE DESIGN: No server-side limit enforcement
    c.execute("SELECT balance FROM users WHERE username=?", (sender,))
    sender_balance = c.fetchone()
    if not sender_balance:
        return "Invalid sender", 403
    if sender_balance[0] < amount:
        return "Insufficient funds", 403

```

### Exploitation:
The app allows any amount to be transferred as long as the user has enough money. There's no limit, no daily cap, and no business rule enforced to prevent abuse. So if the goal of a exploit is to move a huge amount of money in one go.

Let's simply logg in as player[username = player, password = playerpass], and transferred $1000 in one shot to admin using the form.

![alt](/assets/images/insecure/A1.png)

![alt](/assets/images/insecure/A2.png)

That worked because the app never stops you from doing so.


### Fix:

```python

```

## 2. 
