---
platform: android
title: Leakage of Sensitive Data via Logging APIs
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace]
type: [dynamic]
---

## Steps

1. Install and run the app.

2. Navigate to the screen of the mobile app you want to analyse the log output from.

3. Execute a [method trace](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-00xx/) by attaching to the running app, targeting logging APIs and save the output.

## Observation

The **method trace output** contains a list of locations where logging APIs are used in the app for the current execution.

## Evaluation

The test case fails if you can find sensitive data being logged using those APIs.

For example, the following output leaks a key via `Log`:

```shell
Log.println_native(0, 4, "tag", "key: 12345678")
```
