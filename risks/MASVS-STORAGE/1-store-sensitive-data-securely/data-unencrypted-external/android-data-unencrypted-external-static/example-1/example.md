---
platform: android
title: Find common APIs that return paths to External Storage locations
tools: [semgrep]
code: [java]
---

### Sample

{{ use-of-external-store.kt }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-android-data-unencrypted-external.yml }}

{{ run.sh }}

### Observation

The rule has identified 1 location in the code file where a path to external storage is retuened. Make sure you don't store unencrypted code there unintentionally.

{{ output.txt }}

### Evaluation

Review each of the reported instances. In this case, it's only one instance. Line 9 shows the occurrence of API that returns external storage location. Make sure to either:
- encrypt this file if necessary
- move the file to the internal storage
- keep the file in the same location if intended and secure

