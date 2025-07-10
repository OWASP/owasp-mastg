---
title: Insecure WebResourceResponse Implementations
id: MASWE-0073
alias: insecure-webresourceresponse
platform: [android]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-PLATFORM-2, MASVS-CODE-4]
  cwe: [79, 200, 669]

refs:
- https://blog.oversecured.com/Android-Exploring-vulnerabilities-in-WebResourceResponse/
draft:
  description: Using WebResourceResponse instead of WebViewAssetLoader
  topics:
  - Since WebResourceResponse may serve attacker‑controlled HTML/JS, it enables XSS when content isn’t properly sanitized (CWE-79).
  - If an app exposes arbitrary files via XHR in the WebView context, it may be leaking private data (CWE-200).
  - Data or files from a protected internal sphere (such as app-private storage) are exposed to a less trusted sphere, like WebView's JavaScript context or external websites (CWE-669).
status: draft

---

