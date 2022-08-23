---
title: Check if the Keyboard Cache Is Disabled for Text Input Fields
profiles: L2

static_keywords:
  - KeyBoardCache
  - textNoSuggestions

apis:
  -

---

## Overview

When users type in input fields, the software automatically suggests data. This feature can be very useful for messaging apps. However, the keyboard cache may disclose sensitive information when the user selects an input field that takes this type of information.

## Steps

### Static Analysis

1. Inspect the [layout definitions](../../../resources.md#layout-definitions) and find all input fields.

### Dynamic Analysis

1. [install the app](../../techniques.md#install-an-app)
2. Locate all input fields that take sensitive data.
3. Perform manual analysis by typing on those sensitive input fields. If strings are suggested, the keyboard cache has not been disabled for these fields.

## Evaluation

Evaluate if the code for all `TextViews` that take sensitive information have an `inputType="textNoSuggestions"`

To determine wether the input field is sensitive
    - if it's called password
    - if it hides the input `***`

## Mitigation

### Disable Keyboard Cache for Text Input Fields

If the XML attribute `android:inputType` is given the value `textNoSuggestions`, the keyboard cache will not be shown when the input field is selected. The user will have to type everything manually.

The code for all input fields that take sensitive information should include this XML attribute to [disable the keyboard suggestions](https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS "Disable keyboard suggestions"):

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```