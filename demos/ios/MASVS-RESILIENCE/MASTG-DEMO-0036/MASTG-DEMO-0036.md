---
title: Debuggable Entitlement Enabled in the entitlements.plist with rabin2
platform: ios
code: [swift]
id: MASTG-DEMO-0036
test: MASTG-TEST-0261
---

### Sample

The sample code includes the entitlements.plist file with the `get-task-allow' entitlement, which makes the app debuggable.

{{ entitlements.plist }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run @MASTG-TOOL-0129 with the `-OC` options to obtain the entitlements file.

{{ run.sh }}

### Observation

The output reveals the value of the `get-task-allow` entitlement.

{{ output.asm }}

### Evaluation

The test fails because the app is debuggable due to the `get-task-allow` entitlement being present and set to `true`.
