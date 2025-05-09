---
title: Disable JavaScript in WebViews
alias: disable-javascript-in-webviews
id: MASTG-BEST-0012
platform: android
---

If JavaScript is **not required**, explicitly disable it in WebViews by setting [`setJavaScriptEnabled(false)`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29).

Enabling JavaScript in WebViews **increases the attack surface** and can expose your app to severe security risks, including:

- **[Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/):** Malicious JavaScript can execute within the WebView, leading to session hijacking, credential theft, or defacement.
- **Data Exfiltration:** WebViews can access sensitive data such as cookies, tokens, or local files (e.g., via `file://` or `content://` URIs when `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, or `setAllowContentAccess(true)` are enabled) which can be exfiltrated by malicious scripts if `setAllowUniversalAccessFromFileURLs(true)` is set.
- **Unauthorized Device Access:** JavaScript can be used in conjunction with `addJavascriptInterface` to exploit exposed native Android interfaces, leading to remote code execution (RCE).

Sometimes this is not possible due to app requirements. In those cases, ensure that you have implemented proper input validation, output encoding, and other security measures.

Note: sometimes you may want to use alternatives to regular WebViews, such as [Trusted Web Activities](https://developer.android.com/guide/topics/app-bundle/trusted-web-activities) or [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/), which provide a more secure way to display web content in your app. In those cases, JavaScript is handled within the browser environment, which benefits from the latest security updates, sandboxing, and mitigations against common web vulnerabilities such as Cross-Site Scripting (XSS) and Machine-in-the-Middle (MITM) attacks.
