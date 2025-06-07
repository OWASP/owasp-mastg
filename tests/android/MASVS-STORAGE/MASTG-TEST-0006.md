---
masvs_v1_id:
- MSTG-STORAGE-5
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: Determining Whether the Keyboard Cache Is Disabled for Text Input Fields
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0258]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

In the layout definition of an activity, you can define `TextViews` that have XML attributes. If the XML attribute `android:inputType` is given the value `textNoSuggestions`, the keyboard cache will not be shown when the input field is selected. The user will have to type everything manually.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

The code for all input fields that take sensitive information should include this XML attribute to [disable the keyboard suggestions](https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS "Disable keyboard suggestions").

Alternatively, the developer can use the following constants:

| XML `android:inputType` | Code `InputType` | API level |
| -- | --- | - |
| [`textPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_SUGGESTIONS.-,textPassword,-81) | [`TYPE_TEXT_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_PASSWORD "Text password input type") | 3 |
| [`textVisiblePassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91) | [`TYPE_TEXT_VARIATION_VISIBLE_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_VISIBLE_PASSWORD "Text visible password input type") | 3 |
| [`numberPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12) | [`TYPE_NUMBER_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_NUMBER_VARIATION_PASSWORD "A numeric password field") | 11 |
| [`textWebPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_ADDRESS.-,textWebPassword,-e1) | [`TYPE_TEXT_VARIATION_WEB_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_WEB_PASSWORD "Text web password input type") | 11 |

Check the application code to verify that none of the input types are being overwritten. For example, by doing `findViewById(R.id.KeyBoardCache).setInputType(InputType.TYPE_CLASS_TEXT)` the input type of the input field `KeyBoardCache` is set to `text` reenabling the keyboard cache.

Finally, check the minimum required SDK version in the Android Manifest (`android:minSdkVersion`) since it must support the used constants (for example, Android SDK version 11 is required for `textWebPassword`). Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching.

### Dynamic Analysis

Start the app and click in the input fields that take sensitive data. If strings are suggested, the keyboard cache has not been disabled for these fields.
