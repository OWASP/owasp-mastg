---
platform: ios
title: Debuggable Entitlement Enabled in the entitlements.plist with rabin2
code: [swift]
id: MASTG-DEMO-0025
test: MASTG-TEST-0082
---

### Sample

The code snippet below shows sample code that verify the application is debuggable.

{{ entitlements.plist # entitlements_reversed.plist }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run @MASTG-TOOL-0129 with the `-OC` options to obtain the entitlements file.

{{ run.sh }}

### Observation

The output reveals the value of the `get-task-allow` entitlement.

{{ output.asm }}

### Evaluation

The test case fails if the `get-allow-task` flag is explicitly set to `true`. This indicates that the app is configured to allow debugging, which is inappropriate for production environments.
