---
platform: android
title: Listing files inside External Storage 
tools: [adb]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates a file in external storage.

{{ MastgTest.kt }}

### Steps

1. Install an app on your device
2. Execute `run_before.sh`
3. Open an app and exercise it to trigger file creations
4. Execute `run_after.sh`
5. Close the app once you finish testing

{{ run.sh }}

### Observation

There is a list of all created files inside `output.txt`. Their content is inside the `./new_files/` directory.

{{ output.txt }}

### Evaluation

This test fails because the file contains a secretFile.txt.
