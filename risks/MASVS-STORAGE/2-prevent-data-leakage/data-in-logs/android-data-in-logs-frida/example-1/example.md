---
platform: android
title: Common Uses of Insecure Logging APIs
tools: [frida-trace]
code: [kotlin]
---

### Sample

TBD: Explaining what are the test cases in the code for leaking data in log files

{{ snippet.kt }}

### Steps

Execute `frida-trace` against the sample app, tracing logging classes and methods.

{{ run.sh }}

### Observation

The output created by `frida-trace` has identified several instances in the code where log output has been printed.

{{ output.txt }}

### Evaluation

Review each of the reported instances by using keywords and known secrets (e.g. passwords or usernames or values you keyed into the app).
