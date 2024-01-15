---
platform: android
title: Leakage of Sensitive Data via Logging APIs
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace]
type: dynamic
---

## Steps

1. Navigate to the screen of the mobile app you want to analyse the log output from.

2. Execute a [method trace](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-00xx/) by attaching to the running app, targeting logging APIs and save the output.

## Observation

The **method trace output** contains a list of locations where logging APIs are used in the app for the current execution.

## Evaluation

Inspect the code of the app looking for the APIs identified by the static analysis tool.

The test case fails if you can find sensitive data being logged using those APIs.

For example, the following code leaks a password and an IV via `Log`:

```java
Log.i("tag", "key: " + password_secret_key + sec);
Log.w("tag", "test: " + IV);
```
