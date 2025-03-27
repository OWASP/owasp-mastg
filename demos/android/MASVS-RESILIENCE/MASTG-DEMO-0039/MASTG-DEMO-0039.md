---
platform: android
title: Detecting StrictMode PenaltyLog Usage with Semgrep
id: MASTG-DEMO-0039
code: [kotlin]
test: MASTG-TEST-0265
---

### Sample

This sample demonstrates the detection of `StrictMode` penalty log usage in the codebase using Semgrep. The rule identifies instances where `StrictMode.VmPolicy.Builder.penaltyLog()` is invoked.

{{ ../MASTG-DEMO-0037/MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-strictmode.yml }}

{{ run.sh }}

### Observation

The output shows all usages of APIs related to `StrictMode.setVmPolicy`.

{{ output.txt }}

### Evaluation

The test fails because the output shows usages of `StrictMode` APIs, specifically: `StrictMode.setVmPolicy`.