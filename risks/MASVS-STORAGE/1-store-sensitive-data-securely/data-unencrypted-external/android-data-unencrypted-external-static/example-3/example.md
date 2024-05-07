---
platform: android
title: Find MediaStore APIs that writes data to locations shared with other apps
tools: [semgrep]
code: [kotlin]
---

### Sample

{{ use-of-mediastore.kt }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-android-data-unencrypted-external.yml }}

{{ run.sh }}

### Observation

The rule has identified 5 locations in the code which refer to the same MediaStore use.

{{ output.txt }}

### Evaluation

Review the reported instances and make sure to either:
- confirm you intended to make this data public
- store this data in a more strict storage type
