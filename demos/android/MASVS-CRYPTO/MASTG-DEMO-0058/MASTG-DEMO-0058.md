---
platform: android
title: Use of Insecure ECB Block Mode in KeyGenParameterSpec
id: MASTG-DEMO-0058
code: [kotlin]
test: MASTG-TEST-0232
---

### Sample

The code snippet below shows sample code which uses insecure ECB block modes with `KeyGenParameterSpec`.

The method used to configure the block mode is:

```kotlin
public KeyGenParameterSpec.Builder setBlockModes (String... blockModes)
```

As the parameter can be variable, the demo sets the ECB block mode in the following ways:

1. ECB as a single parameter
2. ECB as the second of two parameters
3. ECB as the first of two parameters

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

All information will be written as JSON to `output.txt`.

{{ output.txt }}

### Evaluation

The method `setBlockModes` has now been called three times with ECB as one of the block modes.

You can also evaluate the output automatically using tools like `jq`:

```bash
➜  MASTG-DEMO-0058 git:(DEMO-KeyGenParamSpec) ✗ jq  -s '.[0]|(.class == "android.security.keystore.KeyGenParameterSpec$Builder" and .method == "setBlockModes" and (.inputParameters[0].value | contains(["ECB"])))' output.txt

true
```

The test fails, as key used with these `KeyGenParameterSpec` can now be used used to insecurely encrypt data.

See @MASTG-TEST-0232 for more information.
