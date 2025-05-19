---
title: Verifying iOS Dependencies during runtime
platform: ios
---

> The preferred techniques for analyzing dependencies are @MASTG-TECH-0133 or @MASTG-TECH-0134. This technique, which is described here, should only be used in a black-box environment because it is manual and cannot easily be automated.

When performing an app analysis, it is important to analyze the app's dependencies, which are usually libraries or iOS Frameworks, to ensure they don't contain any known vulnerabilities. Even without the source code, some dependencies can be identified using tools such as @MASTG-TOOL-0038, @MASTG-TOOL-0035, or the `otool -L` command. @MASTG-TOOL-0038 is the recommended tool since it provides the most accurate results and is user-friendly. It contains a module that works with iOS bundles and offers two commands: `list_bundles` and `list_frameworks`.

The `list_frameworks` command lists all of the application's bundles that represent frameworks and their version.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
...
```

With this information it is possible to investigate manually if the frameworks and its version have publicly known vulnerabilities.

The `list_bundles` command lists all of the application's bundles **that are not related to frameworks**. The output contains the executable name, bundle id, version of the library and path to the library.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```
