---
masvs_category: MASVS-STORAGE
platform: android
title: Keyboard Cache
---

When users enter information into input fields, the keyboard software often provides suggestions based on previously entered data. This auto-completion feature can be very useful for messaging apps and other scenarios. However, by default, the Android keyboard may retain (or "cache") input history to offer suggestions and auto-completion. In contexts where sensitive data is entered (such as passwords or PINs), this caching behavior can inadvertently expose sensitive information.

Apps can control this behavior by appropriately configuring the `inputType` attribute on text input fields. There are several ways to do this:

**XML Layouts:**

In the app's XML layout files (typically located in the `/res/layout` directory after unpacking the APK), you can define the input type directly in the `<EditText>` element using the `android:inputType` attribute. For example, setting the input type to `"textPassword"` automatically disables auto-suggestions and caching:

```xml
<EditText
    android:id="@+id/password"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:hint="@string/password_hint"
    android:inputType="textPassword" />
```

**Using the Traditional Android View System:**

When creating input fields in code using the traditional Android view system, you can set the input type programmatically. For example, using an `EditText` in Kotlin:

```kotlin
val input = EditText(context).apply {
    hint = "Enter PIN"
    inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
}
```

**Using Jetpack Compose:**

If you are developing with [Jetpack Compose](https://developer.android.com/develop/ui/compose/text/user-input), you do not use `EditText` directly. Instead, you use composable functions such as `TextField` or `OutlinedTextField` along with parameters like `keyboardOptions` and `visualTransformation` to achieve similar behavior. For example, to create a password field without suggestions:

```kotlin
OutlinedTextField(
    value = password,
    onValueChange = { password = it },
    label = { Text("Enter Password") },
    visualTransformation = PasswordVisualTransformation(),
    keyboardOptions = KeyboardOptions(
        keyboardType = KeyboardType.Password,
        autoCorrect = false
    ),
    modifier = Modifier.fillMaxWidth()
)
```

In this Compose example, the `PasswordVisualTransformation()` masks the input, and `keyboardOptions` with [`KeyboardType.Password`](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:compose/ui/ui-text/src/commonMain/kotlin/androidx/compose/ui/text/input/KeyboardType.kt) helps specify the password input type. The `autoCorrect` parameter is set to `false` to prevent suggestions.

[Internally](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:compose/ui/ui/src/androidMain/kotlin/androidx/compose/ui/text/input/TextInputServiceAndroid.android.kt;l=528-529), the `KeyboardType` enum in Jetpack Compose maps to the Android `inputType` values. For example, the `KeyboardType.Password` corresponds to the following `inputType`:

```kotlin
KeyboardType.Password -> {
    this.inputType =
        InputType.TYPE_CLASS_TEXT or EditorInfo.TYPE_TEXT_VARIATION_PASSWORD
}
```

## Non-Caching Input Types

Regardless of the method used, the app can use the following `inputType` attributes, when applied to `<EditText>` elements, instruct the system to disable suggestions and prevent caching for those input fields:

| XML `android:inputType` | Code `InputType` | API level |
| -- | --- | - |
| [`textNoSuggestions`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=the%20performance%20reasons.-,textNoSuggestions,-80001) | [`TYPE_TEXT_FLAG_NO_SUGGESTIONS`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=TYPE_TEXT_FLAG_NO_SUGGESTIONS. "Text input type") | 3 |
| [`textPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_SUGGESTIONS.-,textPassword,-81) | [`TYPE_TEXT_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_PASSWORD "Text password input type") | 3 |
| [`textVisiblePassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91) | [`TYPE_TEXT_VARIATION_VISIBLE_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_VISIBLE_PASSWORD "Text visible password input type") | 3 |
| [`numberPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12) | [`TYPE_NUMBER_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_NUMBER_VARIATION_PASSWORD "A numeric password field") | 11 |
| [`textWebPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_ADDRESS.-,textWebPassword,-e1) | [`TYPE_TEXT_VARIATION_WEB_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_WEB_PASSWORD "Text web password input type") | 11 |

**Note:** In the MASTG tests we won't be checking the minimum required SDK version in the Android Manifest `minSdkVersion` because we are considering testing modern apps. If you are testing an older app, you should check it. For example, Android API level 11 is required for `textWebPassword`. Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching.

The `inputType` attribute is a bitwise combination of flags and classes. The `InputType` class contains constants for both flags and classes. The flags are defined as `TYPE_TEXT_FLAG_*` and the classes are defined as `TYPE_CLASS_*`. The values of these constants are defined in the Android source code. You can find the source code for the `InputType` class [here](http://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/text/InputType.java "Android InputType class").

The `inputType` attribute in Android is a bitwise combination of these constants:

- **Class constants** (`TYPE_CLASS_*`): Input type (text, number, phone, etc.)
- **Variation constants** (`TYPE_TEXT_VARIATION_*`, etc.): Specific behavior (password, email, URI, etc.)
- **Flag constants** (`TYPE_TEXT_FLAG_*`): Additional modifiers (no suggestions, multi-line, etc.)

For example, this Kotlin code:

```kotlin
inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
```

Where:

- `TYPE_CLASS_TEXT` = 1
- `TYPE_TEXT_VARIATION_PASSWORD` = 128

Results in `1 or 128 = 129`, which is the value you will see in the decompiled code.

**How to decode input type attributes after reverse engineering:**

To decode the `inputType` value, you can use the following masks:

- [`TYPE_MASK_CLASS`](https://developer.android.com/reference/android/text/InputType#TYPE_MASK_CLASS) = `0x0000000F` (to extract the class part)
- [`TYPE_MASK_VARIATION`](https://developer.android.com/reference/android/text/InputType#TYPE_MASK_VARIATION) = `0x00000FF0` (to extract the variation part)
- [`TYPE_MASK_FLAGS`](https://developer.android.com/reference/android/text/InputType#TYPE_MASK_FLAGS) = `0x00FFF000` (to extract the flags part)

You can quickly decode `inputType` values using the masks and the bitwise AND operation e.g. in Python:

```python
129 & 0x0000000F  #   1 (TYPE_CLASS_TEXT)
129 & 0x00000FF0  # 128 (TYPE_TEXT_VARIATION_PASSWORD)
```

**How to find cached data:**

If you write e.g. "OWASPMAS" in the passphrase field a couple of times, the app will cache it and you will be able to find it in the cache database:

```bash
adb shell 'strings /data/data/com.google.android.inputmethod.latin/databases/trainingcachev3.db' | grep -i "OWASPMAS"
OWASPMAS@
OWASPMAS@
OWASPMAS%
```
