---
title: "Running Expo with Tunnel Mode: Test React Native on Your Phone (Even When It’s the Hotspot)"
date: 2025-09-19
categories: [React-Native]
tags: [Application Security, Mobile App Development, Coding]
layout: post
publish: true
---

# How to Use `@expo/ngrok` and `--tunnel` Mode to Run React Native on a Physical Device (Even If Your Phone Is the Hotspot)

So, you just kicked off a React Native project with Expo, and now you want to run it on your **actual physical phone**. But here’s the catch, you’re tethering your PC to your phone’s hotspot and trying to use the same phone to open the Expo app.

Sounds impossible, right?
Not really. That’s where Expo’s **tunnel mode** and the `@expo/ngrok` package save the day.

---

## The Problem

Normally, when you run:

```bash
npx expo start
```

Expo tries to connect your phone and your computer through the **local network (LAN)**. This works fine when both devices are on the same WiFi.

But in our case, your **phone is both the internet provider and the test device**. Since the PC is behind your phone’s hotspot, the LAN option won’t cut it. Your phone can’t “see” itself in that network loop.

That’s where tunneling comes in.

---

## Step 1: Install `@expo/ngrok`

Ngrok is the tool Expo uses under the hood to create a secure tunnel from your PC to the internet. This lets your phone reach your local development server, even if it’s behind the hotspot firewall.

Install it as a dev dependency:

```bash
npm install @expo/ngrok --save-dev
```

Why `--save-dev`? Because this is just a **developer tool**, not something your app needs in production.

---

## Step 2: Start Expo in Tunnel Mode

Once that’s installed, start Expo with the **tunnel** flag:

```bash
npx expo start --tunnel
```

What this does:

* Spins up your development server.
* Ngrok creates a public URL that points back to your machine.
* Expo shares that tunnel with your phone, so it can load the app over the internet.

You’ll see a QR code in your terminal (or Expo Dev Tools in your browser).

---

## Step 3: Open the Project on Your Phone

1. Install the **Expo Go** app from the App Store or Play Store.
2. Scan the QR code that was generated.
3. Watch the magic happen, your phone connects through the tunnel, grabs your project, and runs it in Expo Go.

---

## Why This Works

Even though your phone is the hotspot, the tunnel makes your PC reachable from **outside** the LAN. Your phone simply connects back through that public ngrok URL.

It’s like saying:

> “Hey, I know you’re both the internet provider and the client, but here’s a shortcut link back home.”

---

## Quick Troubleshooting

* If the QR code doesn’t scan, make sure you’re in **tunnel mode** (not LAN).
* Sometimes ngrok may take a few seconds to establish the tunnel, give it a moment.
* If all else fails, restart Expo and your Expo Go app.

---

## Final Thoughts

Using your phone/mobile device as both the hotspot and test device can be a little tricky. But with Expo’s tunnel mode powered by `@expo/ngrok`, you can keep coding wherever you are, no fancy router setup needed.

Next time you’re stuck without WiFi and still want to test your React Native app on your real device, just remember:

```bash
npm install @expo/ngrok --save-dev
npx expo start --tunnel
```

And you’re good to go ✌🏼 .
