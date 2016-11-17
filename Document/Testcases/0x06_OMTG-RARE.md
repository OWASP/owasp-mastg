# Testing Resiliency Against Reverse Engineering

## Overview

This chapter covers defense-in-depth measures that are recommended for apps that process, or give access to, sensitive data or functionality. Lack of any of these controls does not cause a vulnerability - instead, they are meant to increase the app's resiliency against reverse engineering, making it more difficult for adversaries to gain an understanding of the app's internals or extract data from the app.

## Test Cases

### OMTG-RARE-001: Test for Debugging Symbols in Binaries

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.
By default, both ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable. This information is used to resolve references when linking dynamic libraries, and also makes it easier to keep track of the semantics of the code and debugging crashes. It can however be stripped from the release build, unless the goal is to release a dynamic library for public use.

#### Detailed Guides

- [OMTG-RARE-001 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-001)
- [OMTG-RARE-001 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-001)

#### References

- OWASP MASVS: V8-1: "Verify that debugging symbols have been removed from native binaries."
- CWE: N/A

### OMTG-RARE-002: Test for Meaningful Identifiers in Java Bytecode

Because Java classes are trivial to decompile, applying simple obfuscation to the release bytecode is recommended. For Java apps on Android, ProGuard offers an easy way to shrink and obfuscate code. It replaces identifiers such as  class names, method names and variable names with meaningless character combinations. This is a form of layout obfuscation, which is “free” in that it doesn't impact the performance of the program. 

#### Detailed Guides

- [OMTG-RARE-002 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-002)
- [OMTG-RARE-002 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-002)

#### References

- OWASP MASVS: V8-2: "Verify that Java bytecode has been obscured through identifier renaming."
- CWE: N/A

### OMTG-RARE-003: Test Jailbreak / Root Detection

Modern smartphone operating systems implement containerization so that each app is restricted to its own sandbox. A regular app cannot access files outside its dedicated data directories, and access to system APIs is restricted via app privileges. As a result, an app’s sensitive data as well as the integrity of the OS is guaranteed under normal conditions. However, when an adversary gains root access to the mobile operating system, the default protections can be bypassed completely.

The risk of malicious code running as root is higher on rooted or jailbroken devices, as some of the default integrity checks are disabled. Developers of apps that handle highly sensitive data (e.g. banking) should therefore consider implementing checks that prevent the app from running under these conditions.

#### Detailed Guides

- [OMTG-RARE-003 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-003)
- [OMTG-RARE-003 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-003)

#### References

- OWASP MASVS : V8.3: "Verify that the application detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users should be warned, or the app should terminate if the device is rooted."
- CWE : N/A

### OMTG-RARE-004: Test Verification of Installation Source

(todo)

#### Detailed Guides

- [OMTG-RARE-004 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-004)
- [OMTG-RARE-004 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-004)

#### References

- OWASP MASVS : V8.4: "Verify that the app checks its installation source, and only runs if installed from a trusted source."
- CWE : N/A

### OMTG-RARE-005: Test Basic Debugger Detection / Prevention

Debugging is a highly effective way of analyzing the runtime behaviour of an app. It allows the reverse engineer to step through the code, stop execution of the app at arbitrary point, inspect and modify the state of variables, and a lot more. OWASP MASVS L2 requires a the app to implement a simple form of debugger detection / prevention. The app should either actively prevent debuggers from attaching, or terminate when a debugger is detected. 

Testing this control is as simple as attempting to attach a debugger to the app which should either fail, or cause the app to terminate.

#### Detailed Guides

- [OMTG-RARE-005 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-005)
- [OMTG-RARE-005 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-005)

#### References

- OWASP MASVS : V8.5: "Verify that the app has some form of debugger detection and terminates when a debugger is detected, or prevents attaching a debugger using any method. All available means of debugging must be covered (e.g. JDWP and native)."
- CWE : N/A

### OMTG-RARE-006: Test Advanced Jailbreak / Root Detection

#### Detailed Guides

- [OMTG-RARE-006 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-006)
- [OMTG-RARE-006 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-006)

#### References

- OWASP MASVS : V8.6: "Verify that the app implements two or more functionally independent methods of root detection and responds to the presence of a rooted device either by alerting the user or terminating the app."
- CWE : N/A

### OMTG-RARE-007: Test Advanced Debugging Defenses

#### Detailed Guides

- [OMTG-RARE-007 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-007)
- [OMTG-RARE-007 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-007)

#### References

- OWASP MASVS : V8.7: "Verify that the app implements multiple defenses that result in strong resiliency against debugging. All available means of debugging must be covered (e.g. JDWP and native)."
- CWE : N/A

### OMTG-RARE-008: Test File Tampering Detection

#### Detailed Guides

- [OMTG-RARE-008 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-008)
- [OMTG-RARE-008 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-008)

#### References

- OWASP MASVS : V8.8: "Verify that the app detects and responds to tampering with executable files and critical data."
- CWE : N/A

### OMTG-RARE-009: Test Detection of Reverse Engineering Tools

#### Detailed Guides

- [OMTG-RARE-009 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-009)
- [OMTG-RARE-009 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-009)

#### References

- OWASP MASVS : V8.9: "Verify that the app detects the presence of widely used reverse engineering tools, such as code injection tools, hooking frameworks and debugging servers."
- CWE : N/A

### OMTG-RARE-010: Test Basic Emulator Detection

#### Detailed Guides

- [OMTG-RARE-010 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-010)
- [OMTG-RARE-010 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-010)

#### References

- OWASP MASVS : V8.10: "Verify that the app detects whether it is run inside an emulator using any method, and responds by terminating or malfunctioning when an emulator is detected."
- CWE : N/A

### OMTG-RARE-011: Test Memory Tampering Detection

#### Detailed Guides

- [OMTG-RARE-011 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-011)
- [OMTG-RARE-011 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-011)

#### References

- OWASP MASVS : V8.11: "Verify that the app detects modifications of process memory, including relocation table patches and injected code."
- CWE : N/A

### OMTG-RARE-012: Test Variability of Tampering Responses

#### Detailed Guides

- [OMTG-RARE-012 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-012)
- [OMTG-RARE-012 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-012)

#### References

- OWASP MASVS : V8.12: "Verify that that the app implements multiple different responses to tampering, debugging and emulation, including stealthy responses that don't simply terminate the app."
- CWE : N/A

### OMTG-RARE-013: Test Binary Encryption

#### Detailed Guides

- [OMTG-RARE-013 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-013)
- [OMTG-RARE-013 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-013)

#### References

- OWASP MASVS : V8.13: "Verify that all executable files and libraries belonging to the app are either encrypted on the file level and/or important code and data segments inside the executables are encrypted or packed. Trivial static analysis should not reveal important code or data."
- CWE : N/A

### OMTG-RARE-014: Test Device Binding

#### Detailed Guides

- [OMTG-RARE-014 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-014)
- [OMTG-RARE-014 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-014)

#### References

- OWASP MASVS : V8.14: "Verify that the application implements a 'device binding' functionality when a mobile device is treated as being trusted. Verify that the device fingerprint is derived from multiple device properties."
- CWE : N/A

### OMTG-RARE-015: Test Integration of Functional Defenses and Obfuscation

#### Detailed Guides

- [OMTG-RARE-015 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-015)
- [OMTG-RARE-015 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-015)

#### References

- OWASP MASVS : V8.15: "Verify that obfuscating transformations and functional defenses are interdependent and well-integrated throughout the app (e.g. defensive functions are obfuscated)."
- CWE : N/A

### OMTG-RARE-016: Test Advanced Emulator Detection

#### Detailed Guides

- [OMTG-RARE-016 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-016)
- [OMTG-RARE-016 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-016)

#### References

- OWASP MASVS : V8.16: "Verify that the app uses multiple means of emulator detection, and verify that the anti-emulation defenses implement result in strong resiliency against emulation."
- CWE : N/A

### OMTG-RARE-017: Test Integration of SE and/or TEE

#### Detailed Guides

- [OMTG-RARE-017 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-017)
- [OMTG-RARE-017 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-017)

#### References

- OWASP MASVS : V8.17: "Verify that sensitive computations take place in a trusted environment that is isolated from the mobile operating system. Hardware-based SE or TEE should be used whenever available."
- CWE : N/A

### OMTG-RARE-018: Test Advanced Obfuscation

#### Detailed Guides

- [OMTG-RARE-018 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-018)
- [OMTG-RARE-018 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-018)

#### References

- OWASP MASVS : V8.18: "If hardware-based isolation is unavailable, verify that strong obfuscation has been applied to isolate sensitive data and computations, and verify the robustness of the obfuscation."
- CWE : N/A
