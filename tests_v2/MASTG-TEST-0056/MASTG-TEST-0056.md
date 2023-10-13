---
target: system logs - logcat
platform: android
risk: MAS-RISK-0007
title: Leakage of Sensitive Data to Logcat
type: dynamic
---

## Steps

1. Use [logcat](tools/logcat.md) on the command line and filter for the package name (alternatively you can use `logcat` in Android Studio):

    ```bash
    adb logcat | grep “$(adb shell ps | grep <package-name> | awk ‘{print $2}’)”
    ```

2. Launch and use the app going through the various workflows while inputting sensitive data wherever you can.

> Tip: use unique identifiers (like "1111111111111") so that you can easily be find them later in the test output.

## Observation

The **filtered logcat output**.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app within the **filtered logcat output**.

## Example

{{ snippet.kt }}

{{ test.sh }}

{{ output.txt }}
