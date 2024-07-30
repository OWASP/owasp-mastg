---
platform: android
title: External Storage APIs Tracing with Frida
id: MASTG-DEMO-0002
tools: [frida]
code: [kotlin]
test: MASTG-TEST-0201
---

### Sample

The snippet below shows sample code that creates two files in the external storage using the `getExternalFilesDir` method and the `MediaStore` API.

{{ MastgTest.kt }}

### Steps

1. Ensure the app is running on the target device.
2. Execute `run.sh`.
3. Close the app once you finish testing.

The `run.sh` script will inject a Frida script called `script.js`.

{{ run.sh }}

The Frida script will hook and log calls to `open` and `android.content.ContentResolver.insert`.

{{ script.js }}

### Observation

In the output you can see the paths and the relevant stack trace which helps to identify the actual APIs used to write to external storage and their respective callers.

{{ output.txt }}

There are two files written to the external storage:

- `/storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt` written using `java.io.FileOutputStream` from `org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)`
- `content://media/external/downloads/27` written using `android.content.ContentResolver.insert` from `org.owasp.mastestapp.MastgTest.mastgTestMediaStore(MastgTest.kt:44)`

Note that the calls via `ContentResolver.insert` do not write directly to the file system, but to the `MediaStore` content provider, and therefore we can't see the actual file path, instead we see the `content://` URI.

### Evaluation

This test fails because the files are not encrypted and contain sensitive data (a password and an API key). You can further confirm this by reverse engineering the app and inspecting the code as well as retrieving the files from the device.
