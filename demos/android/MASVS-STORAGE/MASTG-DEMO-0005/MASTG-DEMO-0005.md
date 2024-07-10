---
platform: android
title: App Writing to External Storage via the MediaStore API
id: MASTG-DEMO-0005
tools: [semgrep]
code: [kotlin]
test: MASTG-TEST-0202
---

### Sample

The snippet below shows sample code that uses the `MediaStore` API to write a file to shared storage in a path like `/storage/emulated/0/Download/` which does not require any permissions to access and is shared with other apps.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml }}

{{ run.sh }}

### Observation

The rule has identified 2 locations that indicate a use of MediaStore API.

{{ output.txt }}

The first location is the import statement for the `MediaStore` API and the second location is where the `MediaStore` API is used to write to shared storage.

### Evaluation

After reviewing the decompiled code at the locations specified in the output (file and line number) we can conclude that the test fails because the file written by this instance contains sensitive data, specifically a API key.
