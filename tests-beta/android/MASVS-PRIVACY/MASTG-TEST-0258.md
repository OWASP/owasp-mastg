---
platform: android
title: References to Keyboard Caching Attributes in UI Elements
id: MASTG-TEST-0258
type: [static]
weakness: MASWE-0053
profiles: [L2]
---

## Overview

This test verifies that the app appropriately configures text input fields to prevent the [keyboard from caching](../../../Document/0x05d-Testing-Data-Storage.md#keyboard-cache) sensitive information, such as passwords or personal data.

Android apps can configure the behavior of text input fields using XML attributes in the layout files or programmatically in the code. If the app doesn't use [non-caching input types](../../../Document/0x05d-Testing-Data-Storage.md#non-caching-input-types) for sensitive data, the keyboard may cache sensitive information.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Search for XML attributes in the layout files within the `res/layout` directory.
3. Search for calls to the `setInputType` method and the input type values passed to it (@MASTG-TECH-0014).
4. In case the app uses Jetpack Compose, search for calls to [`KeyboardOptions` constructors](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions#public-constructors_1) and their parameters in the reversed code (@MASTG-TECH-0014). Especially `keyboardType` and `autoCorrect`.

## Observation

The output should include:

- All `android:inputType` XML attributes, if using XML for the UI.
- All calls to the `setInputType` method and the input type values passed to it.

## Evaluation

The test case fails if there are any fields handling sensitive data for which the app does not use [non-caching input types](../../../Document/0x05d-Testing-Data-Storage.md#keyboard-cache).
