---
platform: android
title: App Writing Sensitive Data to Sandbox using SharedPreferences
id: MASTG-DEMO-0059
code: [kotlin]
test: MASTG-TEST-0207
---

### Sample

The code snippet below shows sample code which stores sensitive data using `SharedPreferences`. It stores sensitive data using `String` and `StringSet`.

{{ MastgTest.kt }}

### Steps

1. Make sure a mobile phone is attached to your computer with a @MASTG-TOOL-0031 server running on it.
1. Run the script `run.sh`.
1. Run the DEMO on Android while the script is running.
1. Terminate @MASTG-TOOL-0031 by typing `exit` into its shell.

{{ hooks.js # run.sh }}

### Observation

The script will use @MASTG-TOOL-0031 to intercept the methods defined in `hooks.js`.

It will intercept calls to the methods and capture the stacktrace, the decoded parameters the methods is calls with and its decoded return value.

All information will be written as JSON to `output.json`.

{{ output.json }}

### Evaluation

The `SharedPreference` `Editor` was used to write a String and a StringSet unencrypted into the local sandbox.

The test fails, as the data can be potentially extracted from the sandbox using backups or root access on a compromised phone for example.

See @MASTG-TEST-0207 for more information.
