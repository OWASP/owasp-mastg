---
platform: ios
title: Verify App is Debuggable with r2
code: [swift]
id: MASTG-DEMO-0023
test: MASTG-TEST-0082
---

### Sample

The code snippet below shows sample code that verify the application is debuggable.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ debuggable.r2 }}

{{ run.sh }}

### Observation

The output reveals the value of the `get-task-allow` entitlement.

{{ output.txt }}

### Evaluation

The test passes because debugging detection checks are implemented in the app.
