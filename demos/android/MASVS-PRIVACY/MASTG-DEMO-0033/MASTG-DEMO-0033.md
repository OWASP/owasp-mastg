---
platform: android
title: Dangerous Permissions in the AndroidManifest with semgrep
id: MASTG-DEMO-0033
code: [kotlin]
test: MASTG-TEST-0254
---

### Sample

The following is a sample AndroidManifest file that declares 4 dangerous permissions.

{{ AndroidManifest.xml # AndroidManifest_reversed.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample manifest file.

{{ ../../../../rules/mastg-android-dangerous-app-permissions.yaml }}

{{ run.sh }}

### Observation

The rule has identified four instances in the AndroidManifest file where the app declares dangerous permissions.

{{ output.txt }}

### Evaluation

The test fails because the app declares the following dangerous permissions:

- `WRITE_EXTERNAL_STORAGE`
- `READ_CONTACTS`
- `READ_EXTERNAL_STORAGE`
- `ACCESS_FINE_LOCATION`
