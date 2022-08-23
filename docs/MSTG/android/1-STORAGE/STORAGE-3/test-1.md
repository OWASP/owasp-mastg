---
title: Check if Class Logs and Related Code are Removed
profiles: L1, L2

static_keywords:
  - logging
  - error
  - info

apis:
  - android.util.Log
  - System.out.print
  - System.err.print
  - "`Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`"
  - StringBuilder

# NEXT is all generated autom. from the location, name and content

masvs-id: MASVS-STORAGE-2
mstg-id: MSTG-STORAGE-1

techniques:
  - read device logs
  - memory dumping
  - debug
  - method tracing
tools: logcat, grep
resources:
  - log files
  - logs
  - bytecode

references:
  - title: Removing unused strings during ProGuard optimization
    url: https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation
  - title: Debugging with Logcat
    url: https://developer.android.com/tools/debugging/debugging-log.html
  - title: ProGuard's example of removing logging code
    url: https://www.guardsquare.com/en/products/proguard/manual/examples#logging
  
---

## Overview

ProGuard guarantees removal of the `Log.v` method call.

Whether the rest of the code (`new StringBuilder ...`) will be removed depends on the complexity of the code and the [ProGuard version](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation "Removing unused strings during ProGuard optimization").

If the string that will be logged is dynamically constructed, the code that constructs the string may remain in the bytecode. This is a security risk because the (unused) string leaks plain text data into memory, which can be accessed via a debugger or memory dumping.

For example, the following code issues an implicit `StringBuilder` to construct the log statement:

```kotlin
Log.v("Private key tag", "Private key [byte format]: $key")
```

The compiled bytecode, however, is equivalent to the bytecode of the following log statement, which constructs the string explicitly:

```java
Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

## Steps

### Static Analysis

1. [Disassemble](../../techniques.md#disassemble) or [decompile](../../techniques.md#decompile) the app
2. [string search](../../techniques.md#string-search) for [related APIs](#apis)

### Dynamic Analysis

Check the application logs to determine whether log data has been generated; some mobile applications create and store their own logs in the data directory.

Many application developers still use `System.out.println` or `printStackTrace` instead of a proper logging class. Therefore, your testing strategy must include all output generated while the application is starting, running and closing.

1. [install the app](../../techniques.md#install-an-app)
2. do [method tracing](../../techniques.md#method-tracing) on [related APIs](#apis)
3. Use all the mobile app functions at least once
4. [inspect the app data directory](../../techniques.md#inspect-the-data-dir) and look for [app log files](../../../resources.md#app-log-files).
5. [read the app logs](../../techniques.md#read-app-logs) from the [system logs](../../../resources.md#system-logs)

> NOTE: clicking on e.g. [read the app logs](#) will present all needed info, this way we reuse techniques.
> Using those techniques can be done with inputs such as [related APIs](#apis) (here local to the test) or by referring to typical techniques which use/read typical resources such as [app log files](../../../resources.md#app-log-files), [system logs](../../../resources.md#system-logs) or [network trace](../../../resources.md#network-trace)
> Maybe we end up referring to techniques only at this level (?)
> It doesn't make sense to say 
>  - [read the app logs](../../techniques.md#read-app-logs) from the [system logs](../../../resources.md#system-logs)
>  - better: [read the system logs](../../techniques.md#read-the-system-logs)

## Evaluation

## Mitigation

### General ProGuard Configuration

While preparing the production release, you can use tools like [ProGuard](0x08-Testing-Tools.md#proguard) (included in Android Studio). To determine whether all logging functions from the `android.util.Log` class have been removed, check the ProGuard configuration file (proguard-rules.pro) for the following options (according to this [example of removing logging code](https://www.guardsquare.com/en/products/proguard/manual/examples#logging "ProGuard\'s example of removing logging code") and this article about [enabling ProGuard in an Android Studio project](https://developer.android.com/studio/build/shrink-code#enable "Android Developer - Enable shrinking, obfuscation, and optimization")):

```java {}
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

### Implement a custom logging facility and Strip it

Implement a custom logging facility that takes simple arguments and constructs the log statements internally.

```java
SecureLog.v("Private key [byte format]: ", key);
```

Then configure ProGuard to strip its calls.
