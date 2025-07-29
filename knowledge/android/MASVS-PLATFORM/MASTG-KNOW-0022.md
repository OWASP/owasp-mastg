---
masvs_category: MASVS-PLATFORM
platform: android
title: Overlay Attacks
---

Screen overlay attacks occur when a malicious application manages to put itself on top of another application which remains working normally as if it were on the foreground. The malicious app might create UI elements mimicking the look and feel and the original app or even the Android system UI. The intention is typically to make users believe that they keep interacting with the legitimate app and then try to elevate privileges (e.g by getting some permissions granted), stealthy phishing, capture user taps and keystrokes etc.

There are several attacks affecting different Android versions including:

- [**Tapjacking**](https://medium.com/devknoxio/what-is-tapjacking-in-android-and-how-to-prevent-it-50140e57bf44 "What is Tapjacking in Android and How to Prevent It") (Android 6.0 (API level 23) and lower) abuses the screen overlay feature of Android listening for taps and intercepting any information being passed to the underlying activity.
- [**Cloak & Dagger**](https://cloak-and-dagger.org/ "Cloak & Dagger") attacks affect apps targeting Android 5.0 (API level 21) to Android 7.1 (API level 25). They abuse one or both of the `SYSTEM_ALERT_WINDOW` ("draw on top") and `BIND_ACCESSIBILITY_SERVICE` ("a11y") permissions that, in case the app is installed from the Play Store, the users do not need to explicitly grant and for which they are not even notified.
- [**Toast Overlay**](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/ "Android Toast Overlay Attack: Cloak and Dagger with No Permissions") is quite similar to Cloak & Dagger but do not require specific Android permissions to be granted by users. It was closed with CVE-2017-0752 on Android 8.0 (API level 26).

Usually, this kind of attacks are inherent to an Android system version having certain vulnerabilities or design issues. This makes them challenging and often virtually impossible to prevent unless the app is upgraded targeting a safe Android version (API level).

Over the years many known malware like MazorBot, BankBot or MysteryBot have been abusing the screen overlay feature of Android to target business critical applications, namely in the banking sector. This [blog](https://www.infosecurity-magazine.com/opinions/overlay-attacks-safeguard-mobile/ "Dealing with Overlay Attacks: Adopting Built-in Security to Safeguard Mobile Experience") discusses more about this type of malware.
