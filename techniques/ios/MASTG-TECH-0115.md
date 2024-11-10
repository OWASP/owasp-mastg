---
title: Verifying iOS Dependencies during runtime
platform: ios
---

> The preferred technique for analyzing dependencies, is @MASTG-TECH-0113 or @MASTG-TECH-0114. This technique described here should only be used in a black-box environment, as it is manual and and cannot easily be automated.

When performing app analysis, it is important to also analyze the app dependencies, usually in the form of libraries or so-called iOS Frameworks and ensure that they don't contain any known vulnerabilities. Even when you don't have the source code, you can still identify some of the app dependencies using tools like @MASTG-TOOL-0038, @MASTG-TOOL-0035 or the `otool -L` command. @MASTG-TOOL-0038 is the recommended tool, since it provides the most accurate results and it is easy to use. It contains a module to work with iOS Bundles, which offers two commands: `list_bundles` and `list_frameworks`.

The `list_bundles` command lists all of the application’s bundles that are not related to frameworks. The output contains the executable name, bundle id, version of the library and path to the library.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```

The `list_frameworks` command lists all of the application’s bundles that represent frameworks and their version.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
...
```

With this information it is possible to investigate manually if the frameworks and it's version have publicly known vulnerabilities.
