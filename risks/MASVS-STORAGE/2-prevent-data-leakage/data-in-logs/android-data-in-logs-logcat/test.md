---
platform: android
title: Sensitive Data in Logcat
type: dynamic
---

## Steps

1. [Monitor system logs](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/) filtering for the target package name.

2. Launch and use the app going through the various workflows while inputting sensitive data wherever you can.

> Tip: Use unique identifiers (like "1111111111111") so that you can easily be find them later in the test output.

## Observation

The **filtered logcat output**.

## Evaluation

The test case fails if you can find the sensitive data you entered in the app within the **filtered logcat output**.

## Example

{{ snippet.kt }}

{{ test.sh }}

{{ output.txt }}
