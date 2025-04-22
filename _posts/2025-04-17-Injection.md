---
title: "Injection - BreakTheFlask"
date: 2025-04-18
categories: [OWASP, Code review, BreakTheFlask]
tags: [Code review, XSS, SQLi, LDAP]
layout: post
publish: true
---

# Injection Vulnerability

Hey there, fellow hacker! This write-up walks you through exploiting real-world injection flaws in a purposefully vulnerable Flask app. We’re going deep into SQLi, XSS, Command Injection, and LDAP Injection, and yeah, we’ll include the vulnerable code and secure fixes.

Let's dive right in [LAB](https://github.com/DghostNinja/BreakTheFlask.git)

```python
from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os
import ldap3

app = Flask(__name__)

DB_FILE = "vulnerable.db"
LDAP_SERVER = "ldap://localhost:389"
LDAP_BASE_DN = "dc=example,dc=com"

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            INSERT INTO users (username, password)
            VALUES
            ("admin", "password123"),
            ("john", "doe123"),
            ("jane", "secret")
        ''')
        conn.commit()
        conn.close()
        print("[+] Database initialized.")

@app.route('/')
def index():
    return """
    <h1> Injection Vulnerable Web App</h1>
    <p>This app contains multiple injection flaws for research purposes only.</p>
    <ul>
        <li><a href='/login'>SQL Injection (Login Form)</a></li>
        <li><a href='/xss?name=World'>Cross-Site Scripting (XSS)</a></li>
        <li><a href='/terminal'>Command Injection (Terminal)</a></li>
        <li><a href='/ldap-login'>LDAP Injection (Fake Auth)</a></li>
    </ul>
    """

@app.route('/login', methods=['GET', 'POST'])
def sqli():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] SQL Query: {query}")
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()

        if result:
            return f"<h3>Welcome, {username}!</h3><p>Login successful.</p>"
        else:
            return "<p>Login failed. Invalid credentials.</p>"

    return '''
    <h2>SQL Injection Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" /><br>
        <input type="password" name="password" placeholder="Password" /><br>
        <input type="submit" value="Login" />
    </form>
    '''

@app.route('/xss')
def xss():
    name = request.args.get('name', '')
    html = f"""
    <h2>Reflected XSS Demo</h2>
    <form method='GET'>
        <input type='text' name='name' placeholder='Enter your name'>
        <input type='submit' value='Greet'>
    </form>
    <p>Hello, {name}</p>
    """
    return render_template_string(html)

@app.route('/terminal', methods=['GET', 'POST'])
def cmd():
    output = ''
    if request.method == 'POST':
        command = request.form.get('cmd', '')
        print(f"[DEBUG] Executing command: {command}")
        output = os.popen(command).read()

    return f"""
    <h2>Command Execution</h2>
    <form method="POST">
        <input type="text" name="cmd" placeholder="Enter system command">
        <input type="submit" value="Run">
    </form>
    <pre>{output}</pre>
    """

@app.route('/ldap-login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        server = ldap3.Server(LDAP_SERVER, get_info=ldap3.NONE)
        conn = ldap3.Connection(server)
        conn.bind()

        search_filter = f"(&(uid={username})(userPassword={password}))"
        print(f"[DEBUG] LDAP Search Filter: {search_filter}")

        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=ldap3.ALL_ATTRIBUTES
        )

        if conn.entries:
            return f"<h3>Welcome, {username}!</h3><p>LDAP login successful.</p>"
        else:
            return "<p>LDAP login failed.</p>"

    return '''
    <h2>LDAP Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="LDAP Username" /><br>
        <input type="password" name="password" placeholder="LDAP Password" /><br>
        <input type="submit" value="Login" />
    </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
```

---

## 1. SQL Injection (SQLi)
Overview 
SQL Injection occurs when unsanitized user input is embedded directly into an SQL query, allowing attackers to manipulate the query logic. If successful, it can lead to authentication bypass, data leakage, or full DB compromise.

### Vulnerable code:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

### Exploitation:
Visit the vulnerable endpoint at *http://localhost:5000/login*. Enter:

```plaintext
Username: ' OR 1=1 --
Password: anything
```
![alt](/assets/images/B14.png)

What’s happening here is you're closing the original string ('), injecting a logic statement that always returns true (OR 1=1), and commenting out the rest (--). The query becomes:

```python
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
```

![alt](/assets/images/B15.png)

Boom! You’re logged in as the admin user in the database without the correct password.


### Fix:
Use parameterized queries:
```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

## 2. Cross-Site Scripting (XSS)
Overview

Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into webpages viewed by others. It can be used to steal cookies, redirect users, or hijack sessions.


### Vulnerable code:

```python
name = request.args.get('name', '')
html = f"...<p>Hello, {name}</p>..."
return render_template_string(html)
```

### Exploitation:
Navigate to the vulnerable endpoint *http://127.0.0.1:5000/xss?name=World*. 
Enter a basic script tag payload into the input field or the browser's URL

```html
<script>alert('xss')</script>
```

![alt](/assets/images/B16.png)
 We have a reflected XSS displayed on the page.

 ### Fix:
 Use {{ }} in Jinja templates to auto-escape, or better use actual template files, not inline rendering.

 ```python
html = """
<p>Hello, {{ name }}</p>
"""
return render_template_string(html, name=name)
 ```

## 3. Command Injection
Overview 

Command Injection occurs when input from a user is used unsafely in OS-level commands. Attackers can inject arbitrary shell commands that the server will execute.

### Vulnerable code:
 ```python
result = os.popen(command).read()
 ```

### Exploitation:
Navigate to the vulnerable endpoint *http://localhost:5000/terminal*. Try the linux command 

```plaintext
cmd=whoami
```

![alt](/assets/images/B17.png)

![alt](/assets/images/B18.png)

From the above, we got name of the system user(won't be me in real world scenario).

Since the basic test payload worked, you can futher advacnce by trying other payloads:

```plaintext
whoami; ls -la; cat /etc/passwd
```
![alt](/assets/images/B19.png)

We got the directory listing and even sensitive file contents. That’s full RCE (Remote Code Execution) on a real web server.

### Fix:
Use subprocess.run() with a list and no shell. For multi-command support, validate against a whitelist of safe commands or subcommands.

```python
import subprocess
result = subprocess.run(["whoami"], capture_output=True, text=True)
```



## 4. LDAP(Lightweight Directory Access Protocol)
Overview 
LDAP Injection occurs when untrusted user input is used to construct LDAP queries. Attackers can modify query logic to bypass authentication or extract directory data.

### Vulnerable code:
 ```python
username = request.form['username']
password = request.form['password']
ldap_filter = f"(&(uid={username})(userPassword={password}))"

conn.search('dc=example,dc=com', ldap_filter, attributes=['cn'])

 ```


### Exploitation:
This code directly interpolates user input into an LDAP query. To exploit, navigate to vulnerable endpoint *http://localhost:5000/ldap-login*. Let's a basic payload that

```plaintext
Username: admin)(|(uid=*))
Password: anything
```

Constructed filter becomes:
```plaintext
(&(uid=admin)(|(uid=*))(userPassword=anything))
```
The (|(uid=*)) gives you wildcard access.



### Fix:
Use ldap3's safe filter builder. This escapes metacharacters like ) or *, neutralizing injection.
```python
from ldap3.utils.conv import escape_filter_chars

safe_user = escape_filter_chars(username)
safe_pass = escape_filter_chars(password)
search_filter = f"(&(uid={safe_user})(userPassword={safe_pass}))"
```

**N.B:** There is no LDAP server on this lab, that's why there's no image for the exploitation process. However, you can create one and run locally on a docker for practice.

---

## Final Thoughts

+ Use parameterized queries for DB access

+ Escape output and use templates for frontend

+ Never pass user input to os or eval

+ Sanitize LDAP filters and anything string-based


Happy hacking, and stay curious.