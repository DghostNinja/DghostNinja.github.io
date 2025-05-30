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

Let's simply logg in as player[username = player, password = playerpass], and transferred $1000 in one shot to admin using the form.

![alt](/assets/images/insecure/A1.png)

![alt](/assets/images/insecure/A2.png)

That worked because the app never stops you from doing so.


### Fix:
Just adding a server-side check like the one above enforces some basic business rules. You could also implement a daily cap with a transaction history table.

```python
if amount > 500:  # Business rule: no more than $500 per transaction
    return "Transfer amount exceeds limit", 403
```

## 2. 
