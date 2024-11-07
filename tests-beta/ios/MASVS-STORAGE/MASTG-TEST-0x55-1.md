---
platform: ios
title: Sensitive Data Not Excluded From Keyboard Caching
id: MASTG-TEST-0x55-1
type: [static]
---

## Overview

This test checks whether your app prevents the caching of sensitive information entered into text fields. The keyboard may suggest previously entered text when typing in your app or other apps on the device. You can disable the caching mechanism for a text input by setting [UITextAutocorrectionTypeNo](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/uitextautocorrectiontypeno) flag on it.

This test verifies whether your app makes use of `UITextAutocorrectionTypeNo` flag.

iOS prevents the keyboard from caching inputs marked with the [secureTextEntry](https://developer.apple.com/documentation/uikit/uitextinputtraits/1624427-securetextentry) flag by default. Ensure that you use this flag for all password fields

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary to verify if your app uses `UITextAutocorrectionTypeNo`.

2. If you app uses Storyboards or XIB files, check whether the UI elements such as `UITextFields`, `UITextViews`, and `UISearchBars` use `UITextAutocorrectionTypeNo` flag.

## Observation

The output should indicate whether the app uses `UITextAutocorrectionTypeNo`.

## Evaluation

The test case fails if any of the text fields in your app accepts sensitive data but does not use `UITextAutocorrectionTypeNo` or `secureTextEntry`.
