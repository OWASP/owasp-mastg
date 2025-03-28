---
platform: android
title: Detecting StrictMode Uses with Frida
id: MASTG-DEMO-0038
code: [kotlin]
test: MASTG-TEST-0264
status: draft
note: This demo shows how to detect the use of StrictMode at runtime using Frida.
---

### Sample

This sample demonstrates the detection of `StrictMode` uses at runtime using Frida. The app enables a `StrictMode` policy to detect leaked SQLite objects and intentionally leaves a cursor unclosed to trigger the policy.

{{ ../MASTG-DEMO-0037/MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005).
2. Ensure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device.
3. Run `run.sh` to spawn the app with Frida.
4. Observe the Frida script output for detected `StrictMode` uses.

{{ run.sh # script.js }}

### Observation

The Frida script output reveals the runtime usage of `StrictMode` policies, including the detection of leaked SQLite objects.

{{ output.txt }}

### Evaluation

The test passes if the Frida script output shows the runtime usage of `StrictMode` policies. This demonstrates the app's behavior and the effectiveness of the `StrictMode` policy.
