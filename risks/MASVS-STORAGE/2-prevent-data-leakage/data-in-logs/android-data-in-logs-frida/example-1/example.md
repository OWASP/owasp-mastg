---
platform: android
title: Common Uses of Insecure Logging APIs
tools: [frida-trace]
code: [kotlin]
---

### Sample

{{ snippet.kt }}

### Steps

1. Install and run the app.

2. Navigate to the screen of the mobile app you want to analyse the log output from.

3. Run `frida-trace` against the sample code by using run.sh.

{{ run.sh }}

### Observation

The output created by `frida-trace` has identified several instances in the code where log output has been printed.

{{ output.txt }}

### Evaluation

Review each of the reported instances by using keywords and known secrets (e.g. passwords or usernames or values you keyed into the app).
