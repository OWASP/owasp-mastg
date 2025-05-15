---
platform: android
title: Debuggable Flag Enabled in the AndroidManifest with semgrep
id: MASTG-DEMO-0040
code: [kotlin]
test: MASTG-TEST-0226
---

### Sample

The code snippet below shows a sample manifest file with the debuggable flag enabled.

{{ AndroidManifest.xml # AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the manifest file.

{{ ../../../../rules/mastg-android-debuggable-flag.yml }}

{{ run.sh }}

### Observation

The rule has identified the `android:debuggable` attribute in the AndroidManifest.

{{ output.txt }}

### Evaluation

The test case fails because the `android:debuggable` attribute is explicitly set to `true`.
