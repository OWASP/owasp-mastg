---
platform: android
title: Detecting StrictMode Uses with Frida
id: MASTG-DEMO-0038
code: [kotlin]
test: MASTG-TEST-0264
---

### Sample

This sample demonstrates the detection of `StrictMode` uses at runtime using Frida. The app enables a `StrictMode` policy to detect leaked SQLite objects and intentionally leaves a cursor unclosed to trigger the policy.

{{ ../MASTG-DEMO-0037/MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

The Frida script output reveals the runtime usage of `StrictMode`.

{{ output.txt }}

### Evaluation

The test fails because the Frida script output shows the runtime usage of `StrictMode`, specifically:

- `StrictMode.VmPolicy.Builder.penaltyLog`
- `StrictMode.setVmPolicy`
