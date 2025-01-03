---
platform: ios
title: Testing Jailbreak Detection
code: [swift]
id: MASTG-DEMO-0x88
test: MASTG-TEST-0x88
---

### Sample

The code snippet below shows sample code that performs jailbreak detection checks on the device.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ run.sh }}

### Observation

The output reveals the use of file permissions, protocol handlers and file directories in the app.

{{ output.txt }}

### Evaluation

The test passes because jailbreak detection checks are implemented in the app.
