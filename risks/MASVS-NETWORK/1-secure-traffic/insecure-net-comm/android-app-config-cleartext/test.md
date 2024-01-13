---
platform: android
title: App Configuration Allows Cleartext Traffic
type: [static]
---

## Steps

1. [Inspect the Android Manifest](MASTG-TECH-xxxx) and look for `android:usesCleartextTraffic`.
2. [Inspect the Network Security Configuration](MASTG-TECH-xxxx) and look for `cleartextTrafficPermitted`.

## Observation

The **static analysis output** contains a list of locations where cleartext traffic is allowed.

## Evaluation

Inspect the code of the app looking for the locations where cleartext traffic is allowed. The test case fails if you can find any.

## Example

{{ snippet.xml }}

{{ rule.yaml }}

{{ run.sh }}

{{ output.txt }}
