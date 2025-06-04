---
platform: android
title: Testing Local Storage for Input Validation with Semgrep
id: MASTG-DEMO-0054
code: [kotlin]
test: MASTG-TEST-0281
---

### Sample

This code demonstrates improper use of local storage via `SharedPreferences.putString()` and `getString()` for storing sensitive or user-influenced data, including potentially dangerous input like HTML and JSON.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-Local-Storage-for-Input-Validation.yml }}

{{ run.sh }}

### Observation

The output file shows usages of string-based local storage in the code.

{{ output.txt }}

### Evaluation

The test fails because `putString()` and `getString()` were used to store and retrieve structured or potentially user-controlled data, such as:

- Line 48, 49, 67, 68 contains the `putString()`.
- Line 81, 83 contains the `getString()`.
