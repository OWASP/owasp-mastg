---
ID: MSTG-STORAGE-3
TITLE: No sensitive data is written to application logs.
L1: true
L2: true
RISK: |
  Sensitive information contained in log files may become available to:
  * Applications requesting read_logs permissions (< Android xxx)
  * An attacker with physical access to an unlocked device via ADB

  Information may also stil be available even after the user has logged out of the application, as logs are not automtically cleared.
APIS:
 - android.util.Log
 - System.out.print
 - System.err.print
---

## Testing Logs for Sensitive Data (MSTG-STORAGE-3)

### Overview

There are many legitimate reasons to create log files on a mobile device, such as keeping track of crashes, errors, and usage statistics. Log files can be stored locally when the app is offline and sent to the endpoint once the app is online. However, logging sensitive data may expose the data to attackers or malicious applications, and it violates user confidentiality.
You can create log files in several ways. The following list includes two classes that are available for Android:

- [Log Class](https://developer.android.com/reference/android/util/Log.html "Log Class")
- [Logger Class](https://developer.android.com/reference/java/util/logging/Logger.html "Logger Class")

Use a centralized logging class and mechanism and remove logging statements from the production release because other applications may be able to read them.

### Static Analysis

You should check the apps' source code for logging mechanisms by searching for the following keywords:

- Functions and classes, such as:
  - `android.util.Log`
  - `Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`
  - `Logger`

- Keywords and system output:
  - `System.out.print` | `System.err.print`
  - logfile
  - logging
  - logs

While preparing the production release, you can use tools like [ProGuard](0x08-Testing-Tools.md#proguard) (included in Android Studio). To determine whether all logging functions from the `android.util.Log` class have been removed, check the ProGuard configuration file (proguard-rules.pro) for the following options (according to this [example of removing logging code](https://www.guardsquare.com/en/products/proguard/manual/examples#logging "ProGuard\'s example of removing logging code") and this article about [enabling ProGuard in an Android Studio project](https://developer.android.com/studio/build/shrink-code#enable "Android Developer - Enable shrinking, obfuscation, and optimization")):

```java
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

### Dynamic Analysis

Use all the mobile app functions at least once, then identify the application's data directory and look for log files (`/data/data/<package-name>`). Check the application logs to determine whether log data has been generated; some mobile applications create and store their own logs in the data directory.

Many application developers still use `System.out.println` or `printStackTrace` instead of a proper logging class. Therefore, your testing strategy must include all output generated while the application is starting, running and closing. To determine what data is directly printed by `System.out.println` or `printStackTrace`, you can use [`Logcat`](https://developer.android.com/tools/debugging/debugging-log.html "Debugging with Logcat") as explained in the chapter "Basic Security Testing", section "Monitoring System Logs".

Remember that you can target a specific app by filtering the Logcat output as follows:

```bash
$ adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

> If you already know the app PID you may give it directly using `--pid` flag.

You may also want to apply further filters or regular expressions (using `logcat`'s regex flags `-e <expr>, --regex=<expr>` for example) if you expect certain strings or patterns to come up in the logs.