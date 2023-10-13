---
target: app dir logs
platform: android
risk: MAS-RISK-0007
title: Leakage of Sensitive Data via Logging APIs
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace]
type: static
---

## Steps

1. Run a static analysis tool on the app and look for logging APIs.

## Observation

The **static analysis output** contains a list of locations where logging APIs are used in the app.

## Evaluation

Inspect the code of the app looking for the APIs identified by the static analysis tool.

The test case fails if you can find sensitive data being logged using those APIs.

For example, the following code leaks a password and an IV via `Log`:

```java
Log.i("tag", "key: " + password_secret_key + sec);
Log.w("tag", "test: " + IV);
```

## Example

{{ snippet.java }}

{{ run.sh }}

{{ output.txt }}
