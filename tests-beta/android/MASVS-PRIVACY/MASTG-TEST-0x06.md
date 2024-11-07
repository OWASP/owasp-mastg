---
platform: android
title: Sensitive Data Not Excluded From Keyboard Caching
id: MASTG-TEST-0x06
type: [static]
---

## Overview

This test checks whether your app prevents the caching of sensitive information entered into text fields. The keyboard may suggest previously entered text when typing in your app or other apps on the device. You can disable the caching mechanism for a text input by setting [textNoSuggestions](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=the%20performance%20reasons.-,textNoSuggestions,-80001) on it.

This test verifies whether your app makes use of `textNoSuggestions` attribute.

Android also prevents the keyboard from caching inputs marked with the following attributes:

- [textPassword](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType)
- [textVisiblePassword](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91)
- [numberPassword](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12)
- [textWebPassword](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_PHONE.-,text,-1)

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0018 or @MASTG-TOOL-0011 on the APK to verify if your app uses `textNoSuggestions` or the `*password` attribute.

## Observation

The output should indicate whether the app uses no-caching attributes.

## Evaluation

The test case fails if any of the text fields in your app accepts sensitive data but does not use `textNoSuggestions` or `*password` attribute.
