---
platform: android
title: Network security config allows certificates imported on the user's behalf
id: MASTG-DEMO-0037
code: [java]
test: MSTG-TEST-0234-5
---

### Sample

{{ MastgTest.kt # MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-insecure-trust-anchors.yml }}

{{ run.sh }}

### Observation

The rule has identified an element in the network security config that allows certificates imported on the user's behalf.

### Evaluation

Review each of the reported instances.

- Line 11 contains the `<certificates src="user" />` element which allows certificates imported on the user's behalf. 