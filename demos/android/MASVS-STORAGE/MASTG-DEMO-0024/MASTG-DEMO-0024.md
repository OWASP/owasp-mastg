---
platform: android
title: Uses of Caching UI Elements with semgrep
id: MASTG-DEMO-0024
code: [kotlin]
test: MASTG-TEST-0258
---

### Sample

The code sample defines a method that creates a popup dialog for user input where 3 text input fields (`EditText`) are instantiated. For each `EditText`, the `inputType` property is set to define the type of input expected:

- **password**: should not be cached due to `TYPE_TEXT_VARIATION_PASSWORD`
- **passphrase**: should be cached due to `TYPE_CLASS_TEXT`
- **PIN**: should be cached due to `TYPE_CLASS_NUMBER`, despite initially being set to `TYPE_NUMBER_VARIATION_PASSWORD`

A dialog is also created using `AlertDialog.Builder`, and it includes "Sign Up" and "Cancel" buttons.

### Steps

Let's run @MASTG-TOOL-0110 rule against the sample code. The rule uses a pattern that captures every call to `setInputType` along with its argument.

{{ ../../../../rules/mastg-android-keyboard-cache-input-types.yml }}

{{ run.sh }}

### Observation

The rule has detected several instances. For each one, the output shows:

- The line number.
- The object name in the reversed code (e.g. `$this$showPopup_u24lambda_u241` or `input3`).
- The `setInputType` method itself.
- The argument including the input type value (e.g., `129`).

{{ output.txt }}

### Evaluation

The test fails because the app doesn't use non-caching input types for some sensitive fields. Only the first input field (password) is configured correctly. The other two fields (passphrase and PIN) are set to caching input types.

> See the Android [InputType documentation](https://developer.android.com/reference/android/text/InputType) for details about what each numeric value represents.

**(PASS)** Object `showPopup_u24lambda_u241` is set as `129`:

```python
129 & 0x0000000F  #   1 (TYPE_CLASS_TEXT)
129 & 0x00000FF0  # 128 (TYPE_TEXT_VARIATION_PASSWORD)
```

This is correct because it prevents the password from being cached.

**(FAIL)** Object `showPopup_u24lambda_u242` is set as `1` (`TYPE_CLASS_TEXT`).

```python
1 & 0x0000000F  #   1 (TYPE_CLASS_TEXT)
```

This is incorrect because it allows the passphrase to be cached. The correct value should be `129` (`TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD`).

**(FAIL)** Object `input3` is first set to `18`:

```python
18 & 0x0000000F  #   2 (TYPE_CLASS_NUMBER)
18 & 0x00000FF0  #  16 (TYPE_NUMBER_VARIATION_PASSWORD)
```

This would be correct, however, in the reversed code, there's a second `setInputType` call that sets the input type to `2` (`TYPE_CLASS_NUMBER`), which is a caching input type:

```python
2 & 0x0000000F  #   2 (TYPE_CLASS_NUMBER)
```

This is incorrect because it allows the PIN to be cached. The correct value should be `18` (`TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD`).
