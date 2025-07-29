---
platform: android
title: Use of Insecure ECB Block Mode in KeyGenParameterSpec
id: MASTG-DEMO-0058
code: [kotlin]
test: MASTG-TEST-0232
---

### Sample

The code snippet below shows sample code which uses insecure ECB block modes with `KeyGenParameterSpec`.

The code below generates symmetric encryption keys meant to be stored in the Android KeyStore, but it does so using the ECB block mode, which is considered broken due to practical known-plaintext attacks and is disallowed by NIST for data encryption. The method used to set the block modes is [`KeyGenParameterSpec.Builder#setBlockModes(...)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setBlockModes(java.lang.String[])):

```kotlin
public KeyGenParameterSpec.Builder setBlockModes (String... blockModes)
```

Even though the Android KeyStore won't allow encryption using these keys, decryption is still allowed for legacy use.

{{ MastgTest.kt }}

### Steps

1. Make sure a mobile phone is attached to your computer with a @MASTG-TOOL-0031 server running on it.
1. Run the script `run.sh`.
1. Run the DEMO on Android while the script is running.
1. Terminate @MASTG-TOOL-0031 by typing `exit` into its shell.

{{ run.sh # hooks.js }}

### Observation

The script will use @MASTG-TOOL-0031 to intercept the methods defined in `hooks.js`.

It will intercept calls to the methods and capture the stacktrace, the decoded parameters the methods is calls with and its decoded return value.

All information will be written as JSON to `output.json`.

{{ output.json }}

### Evaluation

The method `setBlockModes` has now been called three times with ECB as one of the block modes.

The test fails, as key used with these `KeyGenParameterSpec` can now be used used to insecurely encrypt data.

You can automatically evaluate the output using tools like `jq` as demonstrated in `evaluation.sh`.

{{ evaluate.sh }}

See @MASTG-TEST-0232 for more information.

