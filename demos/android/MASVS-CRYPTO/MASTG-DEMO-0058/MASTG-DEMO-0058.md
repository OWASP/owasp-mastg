---
platform: android
title: Use of Insecure ECB Block Mode in KeyGenParameterSpec
id: MASTG-DEMO-0058
code: [kotlin]
test: MASTG-TEST-0232
---

### Sample

The code below generates symmetric encryption keys meant to be stored in the Android KeyStore, but it does so using the ECB block mode, which is considered broken due to practical known-plaintext attacks and is disallowed by NIST for data encryption. The method used to set the block modes is [`KeyGenParameterSpec.Builder#setBlockModes(...)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setBlockModes(java.lang.String[])):

```kotlin
public KeyGenParameterSpec.Builder setBlockModes (String... blockModes)
```

Even though the Android KeyStore won't allow encryption using these keys, decryption is still allowed for legacy use.

{{ MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ hooks.js # run.sh }}

### Observation

The output shows all instances of block modes mode that were found at runtime. A backtrace is also provided to help identify the location in the code.

{{ output.json }}

### Evaluation

The method `setBlockModes` has now been called three times with ECB as one of the block modes.

The test fails, as key used with these `KeyGenParameterSpec` can now be used used to insecurely encrypt data.

You can automatically evaluate the output using tools like `jq` as demonstrated in `evaluation.sh`.

{{ evaluate.sh }}

See @MASTG-TEST-0232 for more information.

