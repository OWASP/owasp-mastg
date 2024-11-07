---
platform: ios
title: Sensitive Data Not Excluded From Keyboard Caching
id: MASTG-TEST-0x55-1
type: [static]
---

## Overview

This test checks whether your app prevents the caching of sensitive information entered into text fields. Cached text may be suggested later when typing in your app or other apps on the device. You can disable the caching mechanism for a text field by setting [UITextAutocorrectionTypeNo](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/uitextautocorrectiontypeno) on it.

This test verifies whether your app make use of `UITextAutocorrectionTypeNo` flag.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary to verify if your app uses `UITextAutocorrectionTypeNo`.

2. If you app uses Storyboards or XIB files, check whether the UI elements use `UITextAutocorrectionTypeNo` flag.

## Observation

The output should indicate whether the app uses `UITextAutocorrectionTypeNo`.

## Evaluation

The test case fails if any of the text fields in your app accepts sensitive data but does not use `UITextAutocorrectionTypeNo`.
