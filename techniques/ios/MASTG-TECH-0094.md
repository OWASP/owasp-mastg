---
title: Getting Loaded Classes and Methods dynamically
platform: ios
---

In the Frida REPL Objective-C runtime the `ObjC` command can be used to access information within the running app. Within the `ObjC` command the function `enumerateLoadedClasses` lists the loaded classes for a given application.

```bash
$ frida -U -f com.iOweApp

[iPhone::com.iOweApp]-> ObjC.enumerateLoadedClasses()
{
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": [
        "__NSBlockVariable__",
        "__NSGlobalBlock__",
        "__NSFinalizingBlock__",
        "__NSAutoBlock__",
        "__NSMallocBlock__",
        "__NSStackBlock__"
    ],
    "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp": [
        "JailbreakDetection",
        "CriticalLogic",
        "ViewController",
        "AppDelegate"
    ]
}

```

Using `ObjC.classes.<classname>.$ownMethods` the methods declared in each class can be listed.

```bash
[iPhone::com.iOweApp]-> ObjC.classes.JailbreakDetection.$ownMethods
[
    "+ isJailbroken"
]

[iPhone::com.iOweApp]-> ObjC.classes.CriticalLogic.$ownMethods
[
    "+ doSha256:",
    "- a:",
    "- AES128Operation:data:key:iv:",
    "- coreLogic",
    "- bat",
    "- b:",
    "- hexString:"
]
```
