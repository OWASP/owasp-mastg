---
platform: android
title: App Writing to External Storage with Scoped Storage Restrictions
id: MASTG-DEMO-0004
tools: [semgrep]
code: [kotlin]
test: MASTG-TEST-0202
---

### Sample

The snippet below shows sample code that creates a file in external storage using the `getExternalFilesDir` API which returns a path to the app's external files directory (e.g. `/storage/emulated/0/Android/data/org.owasp.mastestapp/files`) and does not require any permissions to access. Scoped storage applies since the app targets Android 12 (API level 31) which is higher than Android 10 (API level 29).

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our semgrep rule against the reversed java code.

{{ ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml }}

{{ run.sh }}

### Observation

The rule has identified one location in the code file where an API, `getExternalFilesDir`, is used to write to external storage with scoped storage restrictions.

{{ output.txt }}

### Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number) we can conclude that the test fails because the file written by this instance contains sensitive data, specifically a password.
