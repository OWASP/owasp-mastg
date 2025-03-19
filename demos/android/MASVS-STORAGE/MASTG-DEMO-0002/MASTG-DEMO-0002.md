---
platform: android
title: External Storage APIs Tracing with Frida
id: MASTG-DEMO-0002
code: [kotlin]
test: MASTG-TEST-0201
---

### Sample

The snippet below shows sample code that creates two files in external storage using the `getExternalFilesDir` method and the `MediaStore` API.

{{ MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

The `run.sh` script injects a @MASTG-TOOL-0001 script named `script.js`. This script hooks and logs calls to the native `open` function and to `android.content.ContentResolver.insert`. It logs the paths of files written to external storage, the caller's stack trace, and additional details such as the `ContentValues` provided.

**Note**: When apps write files using the `ContentResolver.insert()` method, the files are managed by Android's MediaStore and are identified by `content://` URIs, not direct file system paths. This design abstracts the actual file locations, making them inaccessible through standard file system operations like the `open` function in libc. Consequently, when using Frida to hook into file operations, intercepting calls to `open` won't reveal these files.

{{ run.sh # script.js }}

### Observation

In the output you can observe the file paths, the relevant stack traces, and other details that help identify which APIs were used to write to external storage and their respective callers.

{{ output.txt }}

Two files are written to external storage:

- `/storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt`:
    - Written via `java.io.FileOutputStream`
    - Location: `org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)`.
- `secretFile55.txt`:
    - Written via `android.content.ContentResolver.insert`
    - Location: `org.owasp.mastestapp.MastgTest.mastgTestMediaStore(MastgTest.kt:44)`.
    - Found as URI: `content://media/external/downloads/1000000108`.

The `ContentResolver.insert` call used the following `ContentValues`:

- `_display_name: secretFile55.txt`
- `mime_type: text/plain`
- `relative_path: Download`

Using this information we can infer the path of the file written to external storage: `/storage/emulated/0/Download/secretFile55.txt`.

### Evaluation

This test fails because the files are not encrypted and contain sensitive data (such as a password and an API key). This can be further confirmed by reverse-engineering the app to inspect its code and retrieving the files from the device.
