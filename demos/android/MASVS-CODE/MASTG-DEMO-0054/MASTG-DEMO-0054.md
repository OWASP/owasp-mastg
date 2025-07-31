---
platform: android
title: Local Storage for Input Validation with semgrep
id: MASTG-DEMO-0054
code: [kotlin]
test: MASTG-TEST-0281
profiles: [L1, L2]
---

### Sample

The code snippet demonstrates an insecure use of `SharedPreferences` where data is loaded without a proper integrity check, which is a form of input validation for stored data.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-local-storage-for-input-validation.yml }}

{{ run.sh }}

### Observation

The output file correctly identifies the vulnerable pattern where data is loaded without being validated. 

{{ output.txt }}

### Evaluation

The test fails because the rule detected that the app does NOT use an `HMAC` integrity check together with `SharedPreferences`.
