---
platform: android
title: Find MediaStore APIs that writes data to locations shared with other apps
tools: [semgrep]
code: [kotlin]
---

### Sample

{{ MastgTest_reversed.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml }}

{{ run.sh }}

### Observation

The rule has identified 2 locations that indicate a use of MediaStore API.

{{ output.txt }}

### Evaluation

Review the reported instances and make sure to either:

- confirm you intended to make this data public
- store this data in a more strict storage type
