---
platform: android
title: Sensitive Data Not Excluded From Keyboard Caching
id: MASTG-TEST-0224
type: [static]
weakness: MASWE-0053
---

## Overview

This test checks whether the target app prevents the caching of sensitive information entered into text fields. The keyboard may suggest previously entered text when typing in any app on the device.

The following attributes, if present, will prevent the caching mechanism for text inputs.

- [`textNoSuggestions`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=the%20performance%20reasons.-,textNoSuggestions,-80001)
- [`textPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType)
- [`textVisiblePassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91)
- [`numberPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12)
- [`textWebPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_ADDRESS.-,textWebPassword,-e1)

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0018 or @MASTG-TOOL-0011 on the APK looking for uses of any of the above attributes.

## Observation

The output should indicate whether the app uses no-caching attributes.

## Evaluation

The test case fails if any of the text fields in your app accepts sensitive data but do not use no-caching attributes.
