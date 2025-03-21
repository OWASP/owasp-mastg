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

| XML `android:inputType` | Code `InputType` | API level |
| -- | --- | - |
| [`textNoSuggestions`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=the%20performance%20reasons.-,textNoSuggestions,-80001) | [`TYPE_TEXT_FLAG_NO_SUGGESTIONS`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=TYPE_TEXT_FLAG_NO_SUGGESTIONS. "Text input type") | 3 |
| [`textPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_SUGGESTIONS.-,textPassword,-81) | [`TYPE_TEXT_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_PASSWORD "Text password input type") | 3 |
| [`textVisiblePassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91) | [`TYPE_TEXT_VARIATION_VISIBLE_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_VISIBLE_PASSWORD "Text visible password input type") | 3 |
| [`numberPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12) | [`TYPE_NUMBER_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_NUMBER_VARIATION_PASSWORD "A numeric password field") | 11 |
| [`textWebPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_ADDRESS.-,textWebPassword,-e1) | [`TYPE_TEXT_VARIATION_WEB_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_WEB_PASSWORD "Text web password input type") | 11 |

Android apps can use XML or code to create the UI. Many apps use both techniques simultaneously. So you should test both. After unpacking the APK with @MASTG-TOOL-0011, the XML files are in `/res/layout` directory. You can search for the code attributes with @MASTG-TOOL-0018.

Make sure that does not overwrite any input types using the `setInputType` method.

**Note:** In this test we won't be checking the minimum required SDK version in the Android Manifest `minSdkVersion` because we are considering testing modern apps. If you are testing an older app, you should check it. For example, Android API level 11 is required for `textWebPassword`. Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching.

For more information you can consult the MASTG section about ["Keyboard Cache"](../../../Document/0x05d-Testing-Data-Storage.md#keyboard-cache).

## Steps

1. Statically search for the above XML attributes with @MASTG-TOOL-0011
2. Statically search for above code attributes with @MASTG-TOOL-0018
3. Check the code for any `setInputType` API calls that may override the XML attributes

## Observation

The output should include:
- All `android:inputType` XML attributes, if using XML for the UI.
- All `InputType` code attributes, if using code for the UI.
- All calls to the `setInputType` method, if any.

## Evaluation

The test case fails if there are any fields handling sensitive data for which any caching attributes are used. 