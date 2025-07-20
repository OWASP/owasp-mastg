---
masvs_category: MASVS-CODE
platform: ios
id: MASTG-KNOW-0006
title: Debugging Symbols
---

As a good practice, as little explanatory information as possible should be provided with a compiled binary. The presence of additional metadata such as debug symbols might provide valuable information about the code, e.g. function names leaking information about what a function does. This metadata is not required to execute the binary and thus it is safe to discard it for the release build, which can be done by using proper compiler configurations. As a tester you should inspect all binaries delivered with the app and ensure that no debugging symbols are present (at least those revealing any valuable information about the code).

When an iOS application is compiled, the compiler generates a list of debug symbols for each binary file in an app (the main app executable, frameworks, and app extensions). These symbols include class names, global variables, and method and function names which are mapped to specific files and line numbers where they're defined. [Debug builds](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building Your App to Include Debugging Information") of an app place the debug symbols in a compiled binary by default, while release builds of an app place them in a companion _Debug Symbol file_ (dSYM) to reduce the size of the distributed app.
