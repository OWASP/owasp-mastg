---
masvs_category: MASVS-CODE
platform: ios
title: Debugging Information and Debug Symbols
---

When an iOS application is compiled, the compiler generates debug symbols for each binary in the app, including the main executable, frameworks, and extensions. These symbols include class names, global variables, and method and function names, which are mapped to specific source files and line numbers. As a tester, you should examine all binaries included with the app and verify that no meaningful debug symbols are present.

[Debug builds](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building Your App to Include Debugging Information") include these symbols in the compiled binary by default. In contrast, release builds configured with the [Debug Information Format](https://developer.apple.com/documentation/xcode/build-settings-reference#Debug-Information-Format) set to `DWARF with dSYM File` generate separate _Debug Symbol files_ (dSYM), reducing the size of the distributed app.

This approach is similar to [split DWARF](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gsplit-dwarf), common in Linux toolchains. The dSYM files can be uploaded to Apple's symbol servers for [crash report symbolication](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report).

As a best practice, only the metadata required for execution should be included in a compiled binary. Debug symbols and other non-essential metadata can expose internal implementation details, such as function names that indicate their purpose. This information is unnecessary for running the app and should be stripped from release builds using appropriate compiler settings.
