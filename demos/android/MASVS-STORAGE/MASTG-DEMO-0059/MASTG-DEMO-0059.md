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

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

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
