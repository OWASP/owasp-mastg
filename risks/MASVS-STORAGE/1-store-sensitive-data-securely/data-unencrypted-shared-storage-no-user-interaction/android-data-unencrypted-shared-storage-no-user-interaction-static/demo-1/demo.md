---
platform: android
title: App Writing to External Storage without Scoped Storage Restrictions
tools: [semgrep]
code: [kotlin, xml]
---

### Sample

The snippet below shows sample code that creates a file in external storage without using scoped storage APIs. The `getExternalStorageDirectory` API returns a path to the root of the shared external storage (e.g. `/storage/emulated/0`).

{{ MastgTest.kt }}

{{ MastgTest_reversed.java }}

This requires special app access called ["All files access"](https://developer.android.com/preview/privacy/storage#all-files-access), so the `MANAGE_EXTERNAL_STORAGE` permission must be declared in the manifest file.

{{ AndroidManifest.xml }}

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
