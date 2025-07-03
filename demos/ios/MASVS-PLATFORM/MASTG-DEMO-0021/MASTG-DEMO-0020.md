---
platform: ios
title: Uses of Screen Capturing APIs with r2
code: [swift]
id: MASTG-DEMO-0020
test: MASTG-TEST-0240
---

### Sample

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ screen-capture.r2 }}

{{ run.sh }}

### Observation

The output contains all uses of [sceneCaptureState](https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate) and [isCaptured](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured) functions in the binary.

{{ output.txt }}

### Evaluation

The test succeeds because the app includes an API designed to detect screen capturing. While it's unclear whether the app actively uses this API or applies it to relevant screens, its presence suggests that the developer is aware of it.
