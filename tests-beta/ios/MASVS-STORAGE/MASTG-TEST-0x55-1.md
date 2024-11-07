---
platform: ios
title: Sensitive Data Not Excluded From Keyboard Caching
id: MASTG-TEST-0x55-1
type: [static]
weakness: MASWE-0053
---

## Overview

This test checks whether the target app prevents the caching of sensitive information entered into text fields. The keyboard may suggest previously entered text when typing in any app on the device.

The following attributes, if present, will prevent the caching mechanism for text inputs:

- [`UITextAutocorrectionTypeNo`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/uitextautocorrectiontypeno)
- [`secureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/1624427-securetextentry)

If the app uses Storyboards or XIB files, check whether the UI elements such as `UITextFields`, `UITextViews`, and `UISearchBars` use the `UITextAutocorrectionTypeNo` attribute.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary to verify if your app uses the above attributes.

## Observation

The output should indicate whether the app uses no-caching attributes.

## Evaluation

The test case fails if any of the text fields in your app accepts sensitive data but do not use no-caching attributes.
