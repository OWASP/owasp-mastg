---
title: Update the Security Provider
alias: update-security-provider
id: MASTG-BEST-0014
platform: android
---

Android devices vary widely in OS version and update frequency. Relying solely on platform-level security can leave apps exposed to outdated SSL/TLS implementations and known vulnerabilities.

**The GMS Security Provider** (delivered via Google Play Services) addresses this by updating critical cryptographic components—such as `OpenSSL` and `TrustManager`—**independently of the Android OS**. This helps ensure **secure network communication**, even on older or unpatched devices.

It is strongly recommended to check and update the Security Provider **early during app startup**, ideally before making any secure network connections. Follow the Android Developer Documentation on [how to update the Security Provider to protect against SSL exploits](https://developer.android.com/privacy-and-security/security-gms-provider "Updating Your Security Provider to Protect Against SSL Exploits").

If your app needs to support devices both **with and without Google Play Services** (such as Huawei devices, Amazon tablets, or AOSP-based ROMs), implement runtime checks to detect Play Services availability.

- On GMS-enabled devices, use the Security Provider to keep cryptographic libraries up to date.
- On non-GMS devices, consider bundling a secure TLS library like [Conscrypt](https://conscrypt.org) to ensure consistent and strong network security across your entire device fleet.
