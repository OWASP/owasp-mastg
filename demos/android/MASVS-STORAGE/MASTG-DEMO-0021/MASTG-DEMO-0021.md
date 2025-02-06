---
platform: android
title: Uses of Device-Access-Security APIs
id: MASTG-DEMO-0021
code: [kotlin]
test: MASTG-TEST-0216
---

### Sample

The following sample checks whether the device has:

- a passcode set
- a recent OS version
- a OS build intended for the end users

{{ MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-device-access-security-passcode.yml }}
{{ ../../../../rules/mastg-android-device-access-security-sdk-version.yml }}
{{ ../../../../rules/mastg-android-device-access-security-debuggable-system.yml }}

{{ run.sh }}

### Observation

The output files show usages of API that verifies Device-Access-Security

{{ output_passcode.txt }}
{{ output_version.txt }}
{{ output_debuggable_system.txt }}

### Evaluation

The test succeeds because the output files show references to Device-Access-Security APIs
