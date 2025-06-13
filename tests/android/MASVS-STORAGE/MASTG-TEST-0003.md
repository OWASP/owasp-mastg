---
masvs_v1_id:
- MSTG-STORAGE-3
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: Testing Logs for Sensitive Data
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0203, MASTG-TEST-0231]
deprecation_note: New version available in MASTG V2
---

## Overview

This test case focuses on identifying any sensitive application data within both system and application logs. The following checks should be performed:

- Analyze source code for logging related code.
- Check application data directory for log files.
- Gather system messages and logs and analyze for any sensitive data.

As a general recommendation to avoid potential sensitive application data leakage, logging statements should be removed from production releases unless deemed necessary to the application or explicitly identified as safe, e.g. as a result of a security audit.

## Static Analysis

Applications will often use the [Log Class](https://developer.android.com/reference/android/util/Log.html "Log Class") and [Logger Class](https://developer.android.com/reference/java/util/logging/Logger.html "Logger Class") to create logs. To discover this, you should audit the application's source code for any such logging classes. These can often be found by searching for the following keywords:

- Functions and classes, such as:
    - `android.util.Log`
    - `Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`
    - `Logger`

- Keywords and system output:
    - `System.out.print` | `System.err.print`
    - logfile
    - logging
    - logs

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

Note that the example above only ensures that calls to the Log class' methods will be removed. If the string that will be logged is dynamically constructed, the code that constructs the string may remain in the bytecode. For example, the following code issues an implicit `StringBuilder` to construct the log statement:

Example in Java:

```java
Log.v("Private key tag", "Private key [byte format]: " + key);
```

Example in Kotlin:

```kotlin
Log.v("Private key tag", "Private key [byte format]: $key")
```

The compiled bytecode, however, is equivalent to the bytecode of the following log statement, which constructs the string explicitly:

Example in Java:

```java
Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

Example in Kotlin:

```kotlin
Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
```

ProGuard guarantees removal of the `Log.v` method call. Whether the rest of the code (`new StringBuilder ...`) will be removed depends on the complexity of the code and the [ProGuard version](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation "Removing unused strings during ProGuard optimization ").

This is a security risk because the (unused) string leaks plain text data into memory, which can be accessed via a debugger or memory dumping.

Unfortunately, no silver bullet exists for this issue, but one option would be to implement a custom logging facility that takes simple arguments and constructs the log statements internally.

```java
SecureLog.v("Private key [byte format]: ", key);
```

Then configure ProGuard to strip its calls.

## Dynamic Analysis

Use all the mobile app functions at least once, then identify the application's data directory and look for log files (`/data/data/<package-name>`). Check the application logs to determine whether log data has been generated; some mobile applications create and store their own logs in the data directory.

Many application developers still use `System.out.println` or `printStackTrace` instead of a proper logging class. Therefore, your testing strategy must include all output generated while the application is starting, running and closing. To determine what data is directly printed by `System.out.println` or `printStackTrace`, you can use [`Logcat`](https://developer.android.com/tools/debugging/debugging-log.html "Debugging with Logcat") as explained in the chapter "Basic Security Testing", section "Monitoring System Logs".

Remember that you can target a specific app by filtering the Logcat output as follows:

```bash
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

> If you already know the app PID you may give it directly using `--pid` flag.

You may also want to apply further filters or regular expressions (using `logcat`'s regex flags `-e <expr>, --regex=<expr>` for example) if you expect certain strings or patterns to come up in the logs.
