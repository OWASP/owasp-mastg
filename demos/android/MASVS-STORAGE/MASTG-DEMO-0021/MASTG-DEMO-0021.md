---
platform: android
title: Uses of KeyguardManager.isDeviceSecure with semgrep
id: MASTG-DEMO-0021
code: [kotlin]
test: MASTG-TEST-0242
---

### Sample

The following example checks if the device has a passcode set.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-device-passcode-present.yml }}

{{ run.sh }}

### Observation

The output files show usages of API that verifies the presence of passcode.

{{ output.txt }}

### Evaluation

The test passes because the output shows references to passcode verification API.
