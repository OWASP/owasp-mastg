---
platform: android
title: Debuggable Flag Not Disabled with semgrep
id: MASTG-DEMO-0036
code: [kotlin]
---

### Sample

The code snippet below shows a sample code with the debuggable flag not disabled.

{{ AndroidManifest.xml # AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-debuggable-flag-not-disabled.yaml }}

{{ run.sh }}

### Observation

The rule has identified an instance in the AndroidManifest file where the app declares as debuggable.

{{ output.txt }}

### Evaluation

The test fails because the app set the `android:debuggable` attribute to `true`.
