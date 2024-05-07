---
platform: android
title: Find permissions that allows an app to write to locations shared with other apps
tools: [semgrep]
code: [kotlin]
---

### Sample

{{ use-of-external-store.kt }}

### Steps

Let's run our semgrep rule against the sample manifest file.

{{ ../rules/mastg-android-data-unencrypted-external-manifest.yml }}

{{ run.sh }}

### Observation

The rule has identified that the manifest file declares `WRITE_EXTERNAL_STORAGE` permission at line 9.

{{ output.txt }}

### Evaluation

Review your code to make sure you don't store sensitive unencrypted data in the external storage unintentionally.

