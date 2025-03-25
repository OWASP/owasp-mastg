---
platform: android
title: Debuggable Flag Not Disabled with semgrep
id: MASTG-DEMO-0036
code: [kotlin]
test: MASTG-TEST-0226
---

### Sample

The code snippet below shows a sample manifest file with the debuggable flag enabled.

{{ AndroidManifest.xml # AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the manifest file.

{{ ../../../../rules/mastg-android-debuggable-flag-not-disabled.yaml }}

{{ run.sh }}

### Observation

The rule has identified an instance in the AndroidManifest file where the app declares as debuggable.

{{ output.txt }}

### Evaluation

The test case fails if the `debuggable` flag is explicitly set to `true`.
