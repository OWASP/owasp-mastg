---
title: Debuggable Flag Disabled in the AndroidManifest
alias: debuggable-flag-disabled
id: MASTG-BEST-0007
platform: android
---

Ensure the debuggable flag in the AndroidManifest.xml is set to `false` for all release builds.

**Note:** Disabling debugging via the `debuggable` flag is an important first step but does not fully protect the app from advanced attacks. Skilled attackers can enable debugging through various means, such as binary patching (see @MASTG-TECH-0038) to allow attachment of a debugger or the use of binary instrumentation tools like @MASTG-TOOL-0001 to achieve similar capabilities. For apps requiring a higher level of security, consider implementing anti-debugging techniques as an additional layer of defense. Refer to @MASWE-0101 for detailed guidance.
