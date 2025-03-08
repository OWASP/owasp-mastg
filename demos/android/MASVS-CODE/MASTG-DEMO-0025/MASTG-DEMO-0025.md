---
platform: android
title: Uses of Build.VERSION.SDK_INT with semgrep
id: MASTG-DEMO-0025
code: [kotlin]
test: MASTG-TEST-0245
---

### Sample

The following sample uses the `Build.VERSION.SDK_INT` API to check the operating system version.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-sdk-version.yml }}

{{ run.sh }}

### Observation

The output file shows usages of the API that verifies the operating system version.

{{ output.txt }}

### Evaluation

The test passes because the output shows references to SDK version check API.
