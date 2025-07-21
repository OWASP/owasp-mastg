---
masvs_category: MASVS-PLATFORM
platform: android
title: Deep Links
---

_Deep links_ are URIs of any scheme that take users directly to specific content in an app. An app can [set up deep links](https://developer.android.com/training/app-links/deep-linking) by adding _intent filters_ on the Android Manifest and extracting data from incoming intents to navigate users to the correct activity.

Android supports two types of deep links:

- **Custom URL Schemes**, which are deep links that use any custom URL scheme, e.g. `myapp://` (not verified by the OS).
- **Android App Links** (Android 6.0 (API level 23) and higher), which are deep links that use the `http://` and `https://` schemes and contain the `autoVerify` attribute (which triggers OS verification).

**Deep Link Collision:**

Using unverified deep links can cause a significant issue- any other apps installed on a user's device can declare and try to handle the same intent, which is known as **deep link collision**. Any arbitrary application can declare control over the exact same deep link belonging to another application.

In recent versions of Android this results in a so-called _disambiguation dialog_ shown to the user that asks them to select the application that should handle the deep link. The user could make the mistake of choosing a malicious application instead of the legitimate one.

<img src="Images/Chapters/0x05h/app-disambiguation.png" width="50%" />

**Android App Links:**

In order to solve the deep link collision issue, Android 6.0 (API Level 23) introduced [**Android App Links**](https://developer.android.com/training/app-links), which are [verified deep links](https://developer.android.com/training/app-links/verify-site-associations "Verify Android App Links") based on a website URL explicitly registered by the developer. Clicking on an App Link will immediately open the app if it's installed.

There are some key differences from unverified deep links:

- App Links only use `http://` and `https://` schemes, any other custom URL schemes are not allowed.
- App Links require a live domain to serve a [Digital Asset Links file](https://developers.google.com/digital-asset-links/v1/getting-started "Digital Asset Link") via HTTPS.
- App Links do not suffer from deep link collision since they don't show a disambiguation dialog when a user opens them.
