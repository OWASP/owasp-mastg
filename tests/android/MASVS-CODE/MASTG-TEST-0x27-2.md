---
Title: Testing for URL Loading in WebViews
ID: MASTG-TEST-0x27-2
Link: https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/
Platform: android
type: [dynamic]
MASVS v1: ['MSTG-PLATFORM-2']
MASVS v2: ['MASVS-CODE-4']
---

## Overview

By default, navigation events inside of a WebView will redirect to the default browser application. However, it is possible to stay within the WebView and handle all new page loads. This can be dangerous, as the new page may be malicous and interact with either the JavaScript bridge, or phish the user. The application should monitor navigation events inside the WebView to make sure that only legitimate pages are loaded, while others are redirected to the browser application.

## Steps

1. Launch the application and make sure you can hook functions (see @MASTG-TECH-0043).
2. Hook the following functions to see if they are executed:
   1. WebViewClient.shouldOverrideUrlLoading
   2. WebViewClient.shouldInterceptRequest
   3. WebSettings.setSafeBrowsingEnabled
3. Use any WebView inside the app and trigger navigation events

## Observation

The output contains a trace log of which functions are called and their return value.

## Evaluation

The test case fails if:

- Safe Search has been disabled (argument is false)
- The `shouldOverrideUrlLoading` returns false for non-trusted resources
- The `shouldInterceptRequest` handler returns sensitive data
