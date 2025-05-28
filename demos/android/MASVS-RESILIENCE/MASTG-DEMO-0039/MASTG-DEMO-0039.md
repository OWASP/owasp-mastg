---
platform: android
title: Detecting StrictMode PenaltyLog Usage with Semgrep
id: MASTG-DEMO-0039
code: [kotlin]
test: MASTG-TEST-0265
---

### Sample

This sample demonstrates the static detection of `StrictMode` in the app using Semgrep. The app enables a `StrictMode` policy to detect leaked SQLite objects and intentionally leaves a cursor unclosed to trigger the policy.

{{ ../MASTG-DEMO-0037/MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-strictmode.yml }}

{{ run.sh }}

### Observation

The output shows all usages of APIs related to `StrictMode.setVmPolicy`.

{{ output.txt }}

### Evaluation

The test fails because the output shows usages of `StrictMode.setVmPolicy`.
