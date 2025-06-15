---
platform: android
title: Targeting API versions that allow the user to use insecure CAs
id: MASTG-DEMO-0036
code: [kotlin]
test: MSTG-TEST-0234-4
---

### Sample

{{ AndroidManifest.xml # AndroidManifest.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-target-sdk-version.yml }}

{{ run.sh }}

### Observation

The rule has identified one instances in the code where `minSdkVersion` less then 24 is used which opens up the possibility for the use of insecure user defined CAs.

### Evaluation

Review each of the reported instances.

- Line 14 in `AndroidManifest.xml` indicate that the `minSdkVersion` as a version less then 24.
