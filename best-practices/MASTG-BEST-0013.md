---
title: Disable Content Provider Access in WebViews
alias: disable-cont
id: MASTG-BEST-0013
platform: android
---

Unlike other file content access methods from `WebSettings`, the `setAllowContentAccess` method always defaults to `true`. Therefore, **whenever access to content providers isn't explicitly needed**, ensure that the `setAllowContentAccess` method is set to `false` to prevent WebViews from accessing content providers.

## Why is this important?

Having content access enabled in a WebView is not a vulnerability per se; it increases the number of ways an attacker might chain vulnerabilities. For example, if combined with an XSS or other injection vulnerability (or if the WebView is used to display untrusted remote content), it can allow an attacker to read sensitive data, which they can send back to a remote server (e.g. in combination with `setAllowUniversalAccessFromFileURLs`).

Even though there are many "safeguards" (such as CORS restrictions and the fact that a non‑exported provider won't serve data to an arbitrary external caller), the app's own content providers would be accessible, even when not exported; these may have access to the app private storage both in internal or external storage. Also in some cases, depending on the app permissions even to other apps' files in shared/external storage.
