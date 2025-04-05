---
platform: android
title: Sensitive Data Leaked via Screenshots
id: MASTG-DEMO-0021
code: [kotlin]
test: MASTG-TEST-0216
---

### Sample

The snippet below shows sample code that sets `FLAG_SECURE` on an activity that displays sensitive data.

{{ MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the reversed java code.

{{ ../../../../rules/mastg-android-sensitive-data-in-screenshot.yml }}

### Observation

{{ output.txt }}

The rule has identified one location in the code file where an API, `FLAG_SECURE`, is used to prevent capturing the screen.

### Evaluation

This test succeeds because the app used an API to prevent screen recording on a screen with confidential data.
