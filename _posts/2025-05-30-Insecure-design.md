---
title: "Insecure Design - BreakTheFlask"
date: 2025-06-05
categories: [OWASP, Code review, BreakTheFlask]
tags: [Code review, IDOR, BAC, ATO, Password-reset]
layout: post
publish: true
---


# Explaining and Insecure Design
Hello Hacker! Welcome to another BreakTheFlask Session. This should be the last vulnerable code for this specific session.

Today, we will be exploiting and explaining the vulnerabilities caused by Insecure design in this code today.

Using the vulnerable flask code from ==> [BreakTheFlask](https://github.com/DghostNinja/BreakTheFlask.git)


From the insecure design vulnerable code in the repo above, we can find:

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

Let's simply log in as player[username = player, password = playerpass], and transferred $1000 in one shot to admin using the form.

![alt](/assets/images/insecure/A1.png)

![alt](/assets/images/insecure/A2.png)

That worked because the app never stops you from doing so.


### Fix:
Just adding a server-side check like the one above enforces some basic business rules. You could also implement a daily capital with a transaction history table.

```python
if amount > 500:  # Business rule: no more than $500 per transaction
    return "Transfer amount exceeds limit", 403
```

## 2. Race Condition – Double Spending
Overview 

A race condition is a vulnerability that occurs when two or more operations are executed at the same time, and the outcome depends on the sequence or timing of these operations, but the application doesn’t handle the timing conflicts properly.

### Vulnerbale Code:
```python
@app.route('/transfer', methods=['POST'])
def transfer():
    ...
    c.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, sender))
    c.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, recipient))

```


### Exploitation
Let's use the /race_test endpoint, which simulates 5 concurrent transfers of $100 from a single account.

Refresh the balance 

![alt](/assets/images/insecure/A3.png)

![alt](/assets/images/insecure/A4.png)

![alt](/assets/images/insecure/A5.png)

Even though my balance was only $1000, I was able to send $500 in one burst.

### Fix:
Use SQLite transaction locks or atomic operations. Wrap the logic inside a BEGIN IMMEDIATE transaction:

```python
conn.execute('BEGIN IMMEDIATE')
...
if sender_balance[0] < amount:
    conn.rollback()
    return "Insufficient funds", 403
...
conn.commit()
```

## 3. Insecure Password Reset Workflow
Overview

An Insecure Password Reset Workflow is a flawed mechanism for allowing users to reset their passwords, where attackers can bypass identity verification and take over accounts, typically due to missing or weak authentication checks during the reset process.

### Vulnerable Code:
```python
# /reset
code = os.urandom(4).hex()
c.execute("UPDATE users SET reset_code=? WHERE username=?", (code, user))


# /reset_confirm
if dbcode and dbcode[0] == code:
    c.execute("UPDATE users SET password=?, reset_code=NULL WHERE username=?", (newpw, user))

```

### Exploitation
There’s no email validation, no ownership proof. If you know a username (admin), you can reset the password for that user.

Let's head to the */reset* with *username=admin*. Get a reset code from the response.

![alt](/assets/images/insecure/A6.png)

![alt](/assets/images/insecure/A7.png)


Make a POST request to /reset_confirm with the new password and reset code from response.

![alt](/assets/images/insecure/A8.png)

Login with the new password. You are now the admin.

![alt](/assets/images/insecure/A9.png)

### Fix:
- Require email validation and out-of-band confirmation:
- Add CAPTCHA + rate limiting to reduce abuse surface.
- Store the reset code temporarily and validate it securely


## Conclusion

Insecure design isn't just about missing a security header or a weak password policy. It's about **the mindset** behind how an app is built from the ground up. You can follow all the checklists and still end up with broken logic if your core design overlooks real-world abuse scenarios.

Think of it like building a vault with steel walls but leaving the blueprint taped to the front door. The bad guys won’t need to break your encryption if they can just walk through a flaw in how the app works.

Security starts at the drawing board. Validate every flow. Question every assumption. Test what happens when people don’t use your app the way you expect, because attackers never do.
Stay sharp, build with intent, and always think like the ones trying to break in.

We still have other vulnerabilities from the code to be exploited. Try finding them in your free time as practice. 

Catch you in the next write-up. Happy Hacking!✌️