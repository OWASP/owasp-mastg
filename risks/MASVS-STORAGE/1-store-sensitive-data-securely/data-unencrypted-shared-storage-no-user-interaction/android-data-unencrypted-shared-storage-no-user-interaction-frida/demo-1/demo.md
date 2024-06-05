---
platform: android
title: File Tracing
tools: [frida]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates a file in external storage.

{{ MastgTest.kt }}

### Steps

1. Update the Package ID of your app inside `run.sh`
2. Execute `run.sh` against the sample app to trace all usage of file IO.
3. Close the app once you finish testing

{{ run.sh }}

### Observation

There is only one file written to the external storage - `/storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.json`.

{{ output.txt }}

### Evaluation

This test fails since the file contains a password.
