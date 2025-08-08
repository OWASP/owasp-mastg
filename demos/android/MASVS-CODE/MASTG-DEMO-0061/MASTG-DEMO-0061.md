---
platform: android
title: Local Storage for Input Validation with semgrep
id: MASTG-DEMO-0061
code: [kotlin]
test: MASTG-TEST-0288
profiles: [L1, L2]
---

### Sample

The code snippet demonstrates the insecure use of `SharedPreferences`, as data is loaded without an integrity check.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-local-storage-input-validation.yml }}

{{ run.sh }}

### Observation

The rule identifies that data is being loaded without being validated.

{{ output.txt }}

### Evaluation

The test fails as the code does not use an `HMAC` integrity check together with `SharedPreferences` data.
