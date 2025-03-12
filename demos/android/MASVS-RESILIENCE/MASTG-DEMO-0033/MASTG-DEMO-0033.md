---
platform: android
title: Verifying root detection techniques in applications via static analysis
code: [kotlin]
id: MASTG-DEMO-0033
test: MASTG-TEST-0245
---

### Sample

The code snippet below shows sample code that performs root detection checks on the device.

{{ MastgTest.kt }}

### Steps

1. Let's run our @MASTG-TOOL-0110 rule against the reversed java code.

{{ ../../../../rules/mastg-android-root-detection.yml }}

{{ run.sh }}

### Observation

The output reveals the presence of root detection mechanisms in the app, including the use of `Runtime.getRuntime().exec` to check for the `su` command.

{{ output.txt }}

### Evaluation

The test passes because root detection checks are implemented in the app.
