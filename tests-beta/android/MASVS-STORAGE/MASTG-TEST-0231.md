---
platform: android
title: References to Logging APIs
id: MASTG-TEST-0231
apis: [Log, Logger, System.out.print, System.err.print, java.lang.Throwable#printStackTrace, android.util.Log]
type: [static]
weakness: MASWE-0001
---

## Overview

This test verifies if an app uses logging APIs like `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace`.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 to identify all logging APIs.

## Observation

The output should contain a list of locations where logging APIs are used.

## Evaluation

The test fails if an app logs sensitive information from any of the listed locations. Ideally, a release build shouldn't use any logging functions, making it easier to assess sensitive data exposure.

## Mitigation

While preparing the production release, you can use tools like @MASTG-TOOL-0022 (included in Android Studio). To determine whether all logging functions from the `android.util.Log` class have been removed, check the ProGuard configuration file (proguard-rules.pro) for the following options (according to this [example of removing logging code](https://www.guardsquare.com/en/products/proguard/manual/examples#logging "ProGuard\'s example of removing logging code") and this article about [enabling ProGuard in an Android Studio project](https://developer.android.com/studio/build/shrink-code#enable "Android Developer - Enable shrinking, obfuscation, and optimization")):

```default
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

Note that the example above only ensures that calls to the Log class' methods will be removed. If the string that will be logged is dynamically constructed, the code that constructs the string may remain in the bytecode.

Alternatively, you can implement a custom logging facility and disable it at once only for the release builds.
