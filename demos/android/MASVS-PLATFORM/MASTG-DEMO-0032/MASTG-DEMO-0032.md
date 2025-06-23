---
platform: android
title: Uses of WebViews Allowing Local File Access with semgrep
id: MASTG-DEMO-0032
code: [kotlin]
test: MASTG-TEST-0252
---

## Sample

This sample demonstrates the use of WebViews allowing local file access in an Android app and how an attacker could exploit these settings to exfiltrate sensitive data from the app's internal storage using `file://` URIs.

In this demo we focus on the static analysis of the code using semgrep and don't run the app nor the attacker server.

See @MASTG-DEMO-0031 for all the details about the sample and the attack.

{{ MastgTestWebView.kt # AndroidManifest.xml }}

## Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-webview-allow-local-access.yml }}

{{ run.sh }}

## Observation

The output shows all WebView settings found in the code.

{{ output.txt }}

## Evaluation

The test **fails** due to the following WebView settings being configured:

{{ evaluation.txt }}

All these settings are explicitly set to `true` in the code, otherwise, they would remain at their default values (`false`).
