---
masvs_category: MASVS-NETWORK
platform: android
id: MASTG-KNOW-0003
title: Security Provider
---

Android relies on a [security provider](https://developer.android.com/training/articles/security-gms-provider.html "Update your security provider to protect against SSL exploits") to provide SSL/TLS-based connections. The problem with this kind of security provider (one example is [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")), which comes with the device, is that it often has bugs and/or vulnerabilities.

To avoid known vulnerabilities, developers need to make sure that the application will install a proper security provider.
Since July 11, 2016, Google [has been rejecting Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) that use vulnerable versions of OpenSSL.
