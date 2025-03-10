---
platform: android
title: Uses of WebViews Allowing Content Access with semgrep
id: MASTG-DEMO-0029
code: [kotlin]
test: MASTG-TEST-0250
status: new
---

## Sample

This sample demonstrates the use of WebViews allowing content access in an Android app and how an attacker could exploit these settings to exfiltrate sensitive data from the app's internal storage using content URIs.

In this demo we focus on the static analysis of the code using semgrep and don't run the app nor the attacker server.

See @MASTG-DEMO-0030 for all the details about the sample and the attack.

{{ MastgTestWebView.kt # MastgTestWebView_reversed.java # AndroidManifest.xml # AndroidManifest_reversed.xml # filepaths.xml }}

## Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-webview-allow-content-access.yml }}

{{ run.sh }}

## Observation

The output shows **4 results** related to WebView configuration calls. However, it is important to note that the method `setAllowContentAccess` is not explicitly called in the code.

{{ output.txt # output.json }}

## Evaluation

The test **fails** due to the following WebView settings being configured:

- `setJavaScriptEnabled(true)`
- `setAllowUniversalAccessFromFileURLs(true)`

The method `setAllowContentAccess` is not explicitly called in the code, which means it remains at its default value (`true`).

{{ evaluation.txt }}
