---
platform: android
title: WebView Ignoring TLS Errors in onReceivedSslError
id: MASTG-DEMO-0056
code: [kotlin]
test: MSTG-TEST-0284
---

### Sample

This sample connects to <https://tlsexpired.no>, which has an expired SSL certificate, and demonstrates how a WebView ignores SSL/TLS errors by overriding the `onReceivedSslError(...)` method without proper validation. The app calls `proceed()` unconditionally, which allows the connection to continue even when there are TLS errors.

{{ MastgTestWebView.kt # MastgTestWebView_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-onreceivedsslerror.yml }}

{{ run.sh }}

### Observation

The rule identified one instance of the use of the `onReceivedSslError(...)` in the code.

{{ output.txt }}

### Evaluation

The test fails because the app uses a WebView that calls `proceed()` in its `onReceivedSslError(...)` method without validating the TLS error at all. You can manually validate this in the app's reverse-engineered code by inspecting the provided code locations.

In this case:

```java
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                ...
                String message = this.this$0.getSslErrorMessage(error);
                Log.e("MastgTestWebView", "SSL errors onReceivedSslError: " + message);
                Log.e("MastgTestWebView", error.toString());
                handler.proceed();
            }
```

By doing this, the app is effectively ignoring every TLS error even though we can see that the expired certificate error is logged (see @MASTG-TECH-0009):

{{ logcat.txt }}
