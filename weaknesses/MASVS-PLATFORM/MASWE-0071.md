---
title: WebViews Loading Content from Untrusted Sources
id: MASWE-0071
alias: webviews-untrusted-content
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-PLATFORM-2, MASVS-CODE-4]

draft:
  description: WebView objects shouldn't load URLs from untrusted sources. Also, your
    app shouldn't let users navigate to sites that are outside of your control. Whenever
    possible, use an allowlist to restrict the content loaded by your app's WebView
    objects e.g. via WebViewClient.shouldOverrideUrlLoading
  topics:
  - not restricting navigation
  - not using SafeBrowsing
  - loading URL from untrusted sources e.g. intents or deep links
status: placeholder

---

