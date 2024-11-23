---
title: Verifying Android Dependencies during runtime
platform: android
---

> The preferred technique for analyzing dependencies, is @MASTG-TECH-0112 or @MASTG-TECH-0122. This technique described here should only be used in a black-box environment, as it is manual and and cannot easily be automated.

When analysing an application, it's important to analyse the dependencies of the application, usually in the form of libraries, and make sure they don't contain any known vulnerabilities. If the sources are not available, you can decompile the application and check the JAR files. If @MASTG-TOOL-0022D or other obfuscation tools are used properly, the version information about the library is often obfuscated and therefore gone. Otherwise, the information can often still be found in the comments of the Java files of given libraries. Tools such as @MASTG-TOOL-0002 can help to analyse the possible libraries packaged with the application. If you can get the version of the library, either from the comments or from specific methods used in certain versions, you can look for CVEs by hand.
