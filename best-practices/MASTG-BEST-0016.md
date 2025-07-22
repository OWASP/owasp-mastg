---
title: Remove sensitive logs from production builds
alias: remove-logging-in-production
id: MASTG-BEST-0016
platform: ios
---

Ensure that all invocations of logging APIs that expose detailed information about the application or user data are removed. Even if a logging API is only active in developer or debug modes, an attacker could:

- Tamper with the device or the app to force it to display all logs, regardless of the build variant
- Gain deeper insight into the application through static analysis by examining verbose log messages

To ensure maximum security, the safest approach is to completely remove these logging calls.

Below is sample code that demonstrates how to eliminate logging APIs from your application.

## 1. Swift

```swift
#if DEBUG
print("Hello world")
#endif
```

Then you need to set `DEBUG` flag in `Swift Compiler - Custom Flags" > Other Swift Flags` for the development builds.

## 2. Objective-C

```objectivec
#ifdef DEBUG 
# define NSLog (...) NSLog(__VA_ARGS__) 
#else 
# define NSLog (...) 
#endif
```

Then you need to set `DEBUG` flag in `Apple Clang - Preprocessing > Preprocessor Macros` for the development builds.
