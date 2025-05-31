---
title: Insecure Authentication in WebViews
id: MASWE-0040
alias: insecure-webview-auth
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-AUTH-1, MASVS-PLATFORM-2]
  cwe: [287]

refs:
  - https://developer.android.com/reference/android/webkit/WebView#getHttpAuthUsernamePassword(java.lang.String,%20java.lang.String)
  - https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedHttpAuthRequest(android.webkit.WebView,%20android.webkit.HttpAuthHandler,%20java.lang.String,%20java.lang.String)
draft:
  description: e.g. via WebView.getHttpAuthUsernamePassword / WebViewClient.onReceivedHttpAuthRequest
  topics:
  - Using WebView.getHttpAuthUsernamePassword / WebViewClient.onReceivedHttpAuthRequest
status: placeholder

---

