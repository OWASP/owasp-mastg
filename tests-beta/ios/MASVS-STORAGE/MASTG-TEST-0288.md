---
title: References to APIs for Detecting and Preventing Screen Capturing
platform: ios
id: MASTG-TEST-0288
type: [static]
best-practices: [MASTG-BEST-0011]
weakness: MASWE-0055
---

## Overview

This test checks whether an app uses APIs to detect screen capture. On iOS, several APIs allow developers to detect whether the screen is being captured, such as:

- [sceneCaptureState](https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate) - detects screen recording (iOS 17+)
- [isCaptured](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured) - detects screen recording (deprecated in iOS 18)

On iOS, a developer can also prevent the capture of the [UITextField](https://developer.apple.com/documentation/uikit/uitextfield) with [isSecureTextEntry](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry). By default, it's an editable text entry, but it's possible to tweak its properties to make it look like a text UI. This way you can hide the content of sensitive UI elements.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary to identify instances of relevant API usage.

## Observation

The output should include a list of locations where the relevant APIs are used.

## Evaluation

The test case fails if you cannot find the relevant APIs that detects screen recording.
