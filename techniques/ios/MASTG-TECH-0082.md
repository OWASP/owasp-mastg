---
title: Get Shared Libraries
platform: ios
---


To effectively identify and analyze shared libraries within an iOS application, it's important to distinguish between the app's bundled libraries and the system libraries provided by iOS. This distinction helps focus on the components that are unique to the app, thereby reducing noise during security assessments.

- **System Libraries**: Part of the iOS SDK, located in directories such as `/System/Library/Frameworks` or `/usr/lib`. These libraries are standard for all iOS applications and generally don't require detailed analysis unless there is a specific reason.
- **App-Bundled Libraries**: Included in the app bundle, often found in the `Frameworks` directory (`YourApp.app/Frameworks`). They include both first-party (custom) and third-party libraries that the developer intentionally incorporated into the app. They are the primary focus for security assessments. However, note that some **system libraries** may be also bundled with the app to ensure compatibility with specific versions of the iOS SDK so you'd need to filter them out.

Note that we're not considering static libraries, which, unlike dynamic libraries that are loaded at runtime, become part of the app's binary, resulting in a single executable file.

**Strategy**: Use one of the methods below, or a combination of them, to identify shared libraries, and then filter out system libraries to focus on those that are bundled with the app.

## Inspecting the Application Binary

Navigate to the `Frameworks` directory within the application bundle to find the shared libraries. The shared libraries are usually in the form of `.framework` or `.dylib` files.

```bash
ls -1 Frameworks
App.framework
Flutter.framework
libswiftCore.dylib
libswiftCoreAudio.dylib
...
```

## @MASTG-TOOL-0060

You can use the `otool -L` command to list the shared libraries.

```bash
otool -L MASTestApp
MASTestApp:
        /System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 2503.1.0)
        /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.120.2)
        /System/Library/Frameworks/CryptoKit.framework/CryptoKit (compatibility version 1.0.0, current version 1.0.0)
        ...
```

## @MASTG-TOOL-0073

In radare2, you can list the linked libraries using the `il` command.

```bash
r2 MASTestApp
[0x100006e9c]> il
[Linked libraries]
/System/Library/Frameworks/Foundation.framework/Foundation
/usr/lib/libobjc.A.dylib
/usr/lib/libSystem.B.dylib
/System/Library/Frameworks/CryptoKit.framework/CryptoKit
...
```

## @MASTG-TOOL-0074

You can use Objection's command `list_frameworks` to list all the app's bundles that represent Frameworks.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...
```

The `list_bundles` command lists all of the application's bundles **that are not related to frameworks**. The output contains the executable name, bundle id, version of the library and path to the library.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```

## @MASTG-TOOL-0039

The `Process.enumerateModules()` function in Frida's REPL allows enumeration of modules loaded into memory during runtime.

```bash
[iPhone::com.iOweApp]-> Process.enumerateModules()
[
    {
        "base": "0x10008c000",
        "name": "iOweApp",
        "path": "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp",
        "size": 49152
    },
    {
        "base": "0x1a1c82000",
        "name": "Foundation",
        "path": "/System/Library/Frameworks/Foundation.framework/Foundation",
        "size": 2859008
    },
    {
        "base": "0x1a16f4000",
        "name": "libobjc.A.dylib",
        "path": "/usr/lib/libobjc.A.dylib",
        "size": 200704
    },

    ...
```
