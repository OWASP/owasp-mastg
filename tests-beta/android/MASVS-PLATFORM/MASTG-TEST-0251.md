---
platform: android
title: Runtime Use of Content Provider Access APIs in WebViews
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0251
apis: [WebView, WebSettings, getSettings, ContentProvider, setAllowContentAccess, setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled]
type: [dynamic]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013]
profiles: [L1, L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0250.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and either:
    - enumerate instances of `WebView` in the app and list their configuration values
    - or explicitly hook the setters of the `WebView` settings

## Observation

The output should contain a list of WebView instances and corresponding settings.

## Evaluation

**Fail:**

The test fails if all of the following are true:

- `JavaScriptEnabled` is `true`.
- `AllowContentAccess` is `true`.
- `AllowUniversalAccessFromFileURLs` is `true`.

You should use the list of content providers obtained in @MASTG-TEST-0250 to verify if they handle sensitive data.

**Note:** `AllowContentAccess` being `true` does not represent a security vulnerability by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack. Therefore, it is recommended to explicitly set it to `false` if the app does not need to access content providers.

**Pass:**

The test passes if any of the following are true:

- `JavaScriptEnabled` is `false`.
- `AllowContentAccess` is `false`.
- `AllowUniversalAccessFromFileURLs` is `false`.
