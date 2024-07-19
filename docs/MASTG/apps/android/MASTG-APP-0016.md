---
title: Finstergram
platform: android
source: https://github.com/netlight/finstergram
---

Finstergram is an Android application designed with built-in security vulnerabilities to facilitate learning and teaching about common security issues in Android apps. To get started, simply open and build the project in your preferred version of Android Studio.

Functionally, Finstergram acts like a photo vault. The app requires a password to open your secret gallery, ostensibly preventing other users of the phone from accessing them. However, this security is not as foolproof as it seems.

The challenge presented involves having access to a non-rooted phone with the app installed. While you can unlock the phone, the app's password remains unknown. Your task is to identify vulnerabilities in Finstergram's code that could grant access to the secret gallery. Some initial strategies include examining the AndroidManifest file, understanding how the password is validated, investigating broadcast mechanisms, and exploring ways to leverage intents.
