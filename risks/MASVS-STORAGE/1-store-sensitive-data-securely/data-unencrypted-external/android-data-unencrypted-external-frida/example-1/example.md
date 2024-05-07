---
platform: android
title: File Tracing
tools: [frida]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates a file in external storage. You can put this code into your app and follow the steps below to identify a potential data leak.

{{ snippet.kt }}

### Steps

1. Update the Package ID of your app inside `run.sh`
2. Execute `run.sh` against the sample app to trace all usage of file IO.
3. Close the app once you finish testing

{{ run.sh }}

### Observation

The script will output the findings into `output.txt`

{{ output.txt }}

### Evaluation

Review each warning in the output file and make sure you intended to store this file in the external storage.
