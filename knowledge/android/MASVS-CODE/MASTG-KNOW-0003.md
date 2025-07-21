---
masvs_category: MASVS-CODE
platform: android
title: App Signing
---

Android requires all APKs to be digitally signed with a certificate before they are installed or run. The digital signature is used to verify the owner's identity for application updates. This process can prevent an app from being tampered with or modified to include malicious code.

When an APK is signed, a public-key certificate is attached to it. This certificate uniquely associates the APK with the developer and the developer's private key. When an app is being built in debug mode, the Android SDK signs the app with a debug key created specifically for debugging purposes. An app signed with a debug key is not meant to be distributed and won't be accepted in most app stores, including the Google Play Store.

The [final release build](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") of an app must be signed with a valid release key. In Android Studio, the app can be signed manually or via creation of a signing configuration that's assigned to the release build type.

Prior Android 9 (API level 28) all app updates on Android need to be signed with the same certificate, so a [validity period of 25 years or more is recommended](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations"). Apps published on Google Play must be signed with a key that that has a validity period ending after October 22th, 2033.

Three APK signing schemes are available:

- JAR signing (v1 scheme),
- APK Signature Scheme v2 (v2 scheme),
- APK Signature Scheme v3 (v3 scheme).

The v2 signature, which is supported by Android 7.0 (API level 24) and above, offers improved security and performance compared to v1 scheme.
The V3 signature, which is supported by Android 9 (API level 28) and above, gives apps the ability to change their signing keys as part of an APK update. This functionality assures compatibility and apps continuous availability by allowing both the new and the old keys to be used. Note that it is only available via @MASTG-TOOL-0123 at the time of writing.

For each signing scheme the release builds should always be signed via all its previous schemes as well.
