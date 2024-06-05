---
platform: android
title: Find permissions that allows an app to write to locations shared with other apps
tools: [semgrep]
code: [xml]
---

### Sample

{{ AndroidManifest_reversed.xml }}

### Steps

Let's run our semgrep rule against the sample manifest file.

{{ ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction.yml }}

{{ run.sh }}

### Observation

The rule has identified that the manifest file declares `MANAGE_EXTERNAL_STORAGE` permission.

{{ output.txt }}

### Evaluation

Review your code to make sure you don't store sensitive unencrypted data in the external storage unintentionally.

