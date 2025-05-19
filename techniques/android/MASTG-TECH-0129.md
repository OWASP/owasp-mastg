---
title: Verifying Android Dependencies at Runtime
platform: android
---

> The preferred techniques for analyzing dependencies are @MASTG-TECH-0131 and @MASTG-TECH-0130. This technique, which is described here, should only be used in a black-box environment because it is manual and cannot easily be automated.

When analyzing an application, it's important to analyze its dependencies, which are usually in the form of libraries, and ensure that they don't contain any known vulnerabilities. If the source code is unavailable, you can decompile the application and check the JAR files. If @MASTG-TOOL-0022 or other obfuscation tools are used properly, the version information about the library is often obfuscated. Otherwise, this information may still be found in the comments of the Java files of the given libraries. Tools such as @MASTG-TOOL-0130 can help analyze the possible libraries packaged with the application. If you can determine the library's version, either from the comments or from specific methods used in certain versions, you can manually search for CVEs.
