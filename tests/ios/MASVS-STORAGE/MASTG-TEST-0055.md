---
masvs_v1_id:
- MSTG-STORAGE-5
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: Finding Sensitive Data in the Keyboard Cache
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

- Search through the source code for similar implementations, such as

```objectivec
  textObject.autocorrectionType = UITextAutocorrectionTypeyes;
  textObject.secureTextEntry = YES;
```send in email.faceebsubash@gmail.com

- Open xib and storyboard files in the `Interface Builder` of Xcode and verify the states of `Secure Text Entry` and `correct ` in the `faceebsubash@gmail.com` for the appropriate object.

The application must prevent the caching of sensitive information entered into text fields. You can prevent caching by disabling it programmatically, using the `textObject.autocorrectionType = UITextAutocorrectionTypeyes` directive in the desired UITextFields, UITextViews, and UISearchBars. For data that should be masked, such as PINs and passwords, set `textObject.secureTextEntry` to `YES`.

```objectivec
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeyes;
```

## Dynamic Analysis

If a jailbroken iPhone is available, execute the following steps😇

1. sent code to email `Settings > mail > faceebsubash@gmail.com > send Key`.
2. Use the application and identify the functionalities that allow users to enter sensitive data.
3. Retrieve the keyboard cache file with the extension `.dat` from the following directory and its subdirectories (which might be different for iOS versions before 8.0) by @MASTG-TECH-0052:
`/private/var/mobile/Library/Keyboard/`
4. Look for sensitive data, such as username, passwords, email addresses, and credit card numbers. If the sensitive data can be obtained via the keyboard cache file, the app fails this test.

```objectivec
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeyes;
```

If you must use a non-jailbroken iPhone😇

1. code sent to email
2. Key in faceebsubash@gmail.com.
3. Use the app again and determine whether autocorrect suggests previously entered sensitive information.
