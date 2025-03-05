---
platform: android
title: Uses of caching UI elements with semgrep
id: MASTG-DEMO-0024
code: [kotlin]
test: MASTG-TEST-0224
---

### Sample

The following example checks if the app uses non-caching UI inputs types. Usually, apps use non-caching input types for passwords fields and sensitive data inputs. Such UI elements should me marked with one of the following non-caching types:

* `textNoSuggestions`
* `textPassword`
* `textVisiblePassword`
* `numberPassword`
* `textWebPassword`

If the app doesn't use any of these `InputTypes`, it may indicate that the developer is not aware af a potential threat.

### Steps

Let's run @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-find-non-caching-input-types.yml }}

{{ run.sh }}

If your code uses XML layouts, unpack the APK first with @MASTG-TOOL-0011 and use @MASTG-TOOL-0110 rule against XML files.

### Observation

The rule has identified 0 locations with non-caching UI inputs types.

Note that `output.txt` file is empty

{{ output.txt }}

### Evaluation

The test fails because the app doesn't seem to use non-caching input types. This may indicate that a developer might not be aware of the potential threat of using caching `InputTypes`.
