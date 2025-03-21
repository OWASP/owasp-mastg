---
platform: android
title: Uses of caching UI elements with semgrep
id: MASTG-DEMO-0024
code: [kotlin]
test: MASTG-TEST-0224
---

### Sample

The code sample defines a method that creates a popup dialog for user input where 3 text input fields (`EditText`) are instantiated. For each `EditText`, the method calls `setInputType` with an integer value to configure the behavior of the input field.

The input fields are:

- **password**: should not be cached due to `TYPE_TEXT_VARIATION_PASSWORD`
- **passphrase**: should be cached due to `TYPE_CLASS_TEXT`
- **PIN**: should be cached due to `TYPE_CLASS_NUMBER`, despite initally being set to `TYPE_NUMBER_VARIATION_PASSWORD`

### Steps

Let's run @MASTG-TOOL-0110 rule against the sample code. The rule uses a pattern that captures every call to `setInputType` along with its argument.

{{ ../../../../rules/mastg-android-find-non-caching-input-types.yml }}

{{ run.sh }}

### Observation

The rule has detected several instances. For each one, the output shows:

- The line number.
- The object name in the reversed code (e.g. `$this$showPopup_u24lambda_u241` or `input3`)
- The `setInputType` method itself
- The argument including the input type value (e.g., `128`).

{{ output.txt }}

### Evaluation

The test fails because the app doesn't use non-caching input types for some sensitive fields. Only the first input field (password) is configured correctly. The other two fields (passphrase and PIN) are set to caching input types.

Here's a summary:

- (PASS) Object `showPopup_u24lambda_u241` is set as `128` (`TYPE_TEXT_VARIATION_PASSWORD`).
- (FAIL) Object `showPopup_u24lambda_u242` is set as `1` (`TYPE_CLASS_TEXT`).
- (FAIL) Object `input3` is set as:
    - `18` (`TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD`, which is 2 + 16 = 18).
    - `2` (`TYPE_CLASS_NUMBER`).

See the Android [InputType documentation](https://developer.android.com/reference/android/text/InputType) for details about what each numeric value represents (often through a combination of flags and classes).

If you write e.g. "OWASPMAS" in the passphrase field a couple of times, the app will cache it and you will be able to find it in the cache database:

```bash
adb shell 'strings /data/data/com.google.android.inputmethod.latin/databases/trainingcachev3.db' | grep -i "OWASPMAS"
OWASPMAS@
OWASPMAS@
OWASPMAS%
```
