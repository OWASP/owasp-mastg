---
platform: android
title: Find common APIs that return paths to External Storage locations
tools: [semgrep]
code: [kotlin]
---

### Demo

{{ use-of-external-store.kt }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-android-data-unencrypted-external.yml }}

{{ run.sh }}

### Observation

The rule has identified one location in the code file where a path to external storage is returned.

{{ output.txt }}

### Evaluation

Review the decompiled code at the location specified in the output (file and line number). This test fails because the file written by this instance contains sensitive data, specifically a password.

