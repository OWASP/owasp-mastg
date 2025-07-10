---
platform: android
title: Uses of WebViews Allowing Content Access with semgrep
id: MASTG-DEMO-0029
code: [kotlin]
test: MASTG-TEST-0250
---

## Sample

This sample demonstrates how a WebView in an Android app, when configured to allow content access, can be exploited by an attacker to interact with exposed `content://` URIs. While `content://` URIs are simply interfaces to content providers, a misconfigured or overly permissive content provider may grant access to sensitive resources—such as internal app files. In this example, internal file access is used as a representative impact to illustrate the full attack chain, though actual impacts depend on the specific behavior of the content provider.

In this demo we focus on the static analysis of the code using semgrep and don't run the app nor the attacker server.

See @MASTG-DEMO-0030 for all the details about the sample and the attack.

{{ MastgTestWebView.kt # MastgTestWebView_reversed.java # AndroidManifest.xml # AndroidManifest_reversed.xml # filepaths.xml }}

## Steps

Run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-webview-allow-local-access.yml }}

{{ run.sh }}

## Observation

The output shows **4 results** related to WebView configuration calls. However, it is important to note that the method `setAllowContentAccess` is not explicitly called in the code.

{{ output.txt }}

## Evaluation

The test **fails** due to the following WebView settings being configured:

{{ evaluation.txt }}

The method `setAllowContentAccess` is not explicitly called in the code, which means it remains at its default value (`true`).
