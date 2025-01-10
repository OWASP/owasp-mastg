---
platform: ios
title: Uses of Jailbreak Detection Techniques with r2
code: [swift]
id: MASTG-DEMO-0021
test: MASTG-TEST-0240
---

### Sample

The code snippet below shows sample code that performs jailbreak detection checks on the device.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ jailbreak_detection.r2 }}

{{ run.sh }}

### Observation

The output reveals the use of file permissions, protocol handlers and file directories in the app.

{{ output.asm }}

### Evaluation

The test passes because jailbreak detection checks are implemented in the app.
