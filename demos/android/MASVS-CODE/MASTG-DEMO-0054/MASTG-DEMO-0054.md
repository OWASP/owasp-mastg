---
platform: android
title: Local Storage for Input Validation with semgrep
id: MASTG-DEMO-0054
code: [kotlin]
test: MASTG-TEST-0281
---

### Sample

The code snippet shows the improper use of local storage via `putString()` and `getString()` for storing sensitive data.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-local-storage-for-input-validation.yml }}

{{ run.sh }}

### Observation

The output file shows usages of string based local storage in the code.

{{ output.txt }}

### Evaluation

The test fails because `putString()` and `getString()` were found in the code.

- Line 48, 49, 67, 68 contains the `putString()`.
- Line 81, 83 contains the `getString()`.
