---
platform: android
title: Find common APIs that return paths to Public External Storage locations
tools: [semgrep]
code: [kotlin, xml]
---

### Sample

The snippet below shows sample code that creates a file in external storage.

{{ MastgTest_reversed.java }}

This requires special app access called ["All files access"](https://developer.android.com/preview/privacy/storage#all-files-access), so the following permission must be declared in the manifest file.

{{ AndroidManifest_reversed.xml }}

### Steps

Let's run our semgrep rule against the reversed java code.

{{ ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml }}

And another one against the sample manifest file.

{{ ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml }}

{{ run.sh }}

### Observation

The rule has identified one location in the code file where an API, `getExternalStorageDirectory`, is used to write to external storage.

{{ output.txt }}

The rule has also identified that the manifest file declares `MANAGE_EXTERNAL_STORAGE` permission.

{{ output2.txt }}

### Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number) we can conclude that the test fails because the file written by this instance contains sensitive data, specifically a password.
