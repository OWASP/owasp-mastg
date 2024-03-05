---
platform: android
title: File Tracing
tools: [frida-trace]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates a file in external storage. You can put this code into your app and follow the steps to see a sample usage of `frida-trace` to identify a potential data leak.

{{ snippet.kt }}

### Steps

Execute `frida-trace` against the sample app to trace all usage of file IO.

{{ run.sh }}

### Observation

`frida-trace` has identified one file path in the external storage that the app opened.

{{ output.txt }}

### Evaluation

Review each of the reported instances by manually opening a file and inspecting its content.

NOTE: If you want to test more file locations than only the file locations inside the external storage, remove `grep` from the script.
