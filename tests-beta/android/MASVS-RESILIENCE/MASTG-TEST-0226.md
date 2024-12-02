---
title: Debuggable Flag Enabled in the AndroidManifest
platform: android
id: MASTG-TEST-0226
type: [static]
weakness: MASWE-0067
---

## Overview

This test case checks if the app has the `debuggable` flag ([`android:debuggable`](https://developer.android.com/guide/topics/manifest/application-element#debug)) set to `true` in the `AndroidManifest.xml`. When this flag is enabled, it allows the app to be debugged enabling attackers to inspect the app’s internals, bypass security controls, or manipulate runtime behavior.

Although having the `debuggable` flag set to `true` [is not considered a direct vulnerability](https://developer.android.com/privacy-and-security/risks/android-debuggable), it significantly increases the attack surface by providing unauthorized access to app data and resources, particularly in production environments.

## Steps

1. Obtain the `AndroidManifest.xml` file using @MASTG-TECH-0117.
2. Search for the `debuggable` flag:
    - Look for `android:debuggable` if analyzing raw XML using tools like @MASTG-TOOL-0011.
    - Look for `application-debuggable` if using @MASTG-TOOL-0124.

## Observation

The output should explicitly show whether the `debuggable` flag is set (`true` or `false`). If the flag is not specified, it is treated as `false` by default for release builds.

## Evaluation

The test case fails if the `debuggable` flag is explicitly set to `true`. This indicates that the app is configured to allow debugging, which is inappropriate for production environments.

To mitigate this issue, ensure the debuggable flag in the AndroidManifest.xml is set to false for all release builds.

**Note:** Disabling debugging via the `debuggable` flag is an important first step but does not fully protect the app from advanced attacks. Skilled attackers can enable debugging through various means, such as binary patching (see @MASTG-TECH-0038) to allow attachment of a debugger or the use of binary instrumentation tools like @MASTG-TOOL-0001 to achieve similar capabilities. For apps requiring a higher level of security, consider implementing anti-debugging techniques as an additional layer of defense. Refer to @MASWE-0101 for detailed guidance.
