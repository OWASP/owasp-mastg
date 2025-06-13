---
title: Disable Content Provider Access in WebViews
alias: disable-cont
id: MASTG-BEST-0013
platform: android
---

Unlike other file content access methods from `WebSettings`, the `setAllowContentAccess` method always defaults to `true`. Therefore, **whenever access to content providers isn't explicitly needed**, ensure that the `setAllowContentAccess` method is set to `false` to prevent WebViews from accessing content providers.

## Why is this important?

Enabling content access in a WebView is not a vulnerability per se; it increases the number of ways an attacker could chain vulnerabilities. For example, if combined with an XSS or other injection vulnerability (or if the WebView is used to display untrusted remote content), it can allow an attacker to read sensitive data that they can send back to a remote server.

Although there are many "safeguards" (such as CORS restrictions and the fact that a non-exported provider won't serve data to any external caller), the app's own content providers would be accessible even if they were not exported; they may have access to the app's private storage, both in internal and external storage. Also in some cases even other apps' files in shared/external storage, depending on the app permissions (e.g. `READ_MEDIA_IMAGES`, etc.).
