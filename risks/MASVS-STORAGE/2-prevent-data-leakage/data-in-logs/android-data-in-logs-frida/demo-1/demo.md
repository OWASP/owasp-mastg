---
platform: android
title: Tracing Common Logging APIs Looking for Secrets
tools: [frida-trace]
code: [kotlin]
---

### Sample

The snippet contains many calls to logging APIs which are used to print out secrets such as passwords or IVs.

{{ snippet.kt }}

### Steps

Execute `frida-trace` against the sample app, tracing logging classes and methods.

{{ run.sh }}

### Observation

`frida-trace` has identified several instances where log output has been printed.

{{ output.txt }}

As a reference, this is the corresponding logcat output obtained from Android Studio.

{{ logcat_output.txt }}

### Evaluation

Review each of the reported instances by using keywords and known secrets (e.g. passwords or usernames or values you keyed into the app).

Note: You could refine the test to input a known secret and then search for it in the logs.
