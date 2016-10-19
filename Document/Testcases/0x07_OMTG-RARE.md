# Testing Resiliency Against Reverse Engineering

## Overview

This chapter covers defense-in-depth measures that are recommended for apps that process, or give access to, sensitive data or functionality. Lack of any of these controls does not cause a vulnerability - instead, they are meant to increase the app's resiliency against reverse engineering, making it more difficult for adversaries to gain an understanding of the app's internals or extract data from the app.

## Test Cases

### OMTG-RARE-001: Test for Debugging Symbols in Binaries

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.
By default, both ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable. This information is used to resolve references when linking dynamic libraries, and also makes it easier to keep track of the semantics of the code and debugging crashes. It can however be stripped from the release build, unless the goal is to release a dynamic library for public use.

#### Detailed Guides

- [OMTG-DATAST-001 Android](0x07a_OMTG-RARE_Android.md#OMTG-RARE-001)
- [OMTG-DATAST-001 iOS](0x07b_OMTG-RARE_iOS.md#OMTG-DATAST-001)

#### References

- OWASP MASVS: V8-1: "Verify that debugging symbols have been removed from native binaries."
- CWE: N/A

### OMTG-RARE-002: Test for Meaningful Identifiers in Java Bytecode
[General description]

#### Detailed Guides

- [OMTG-RARE-002 Android](0x08a_OMTG-RARE_Android.md#OMTG-RARE-002)
- [OMTG-RARE-002 iOS](0x08b_OMTG-RARE_iOS.md#OMTG-RARE-002)

#### References

- OWASP MASVS: V8-2: "Verify that Java bytecode has been obscured through identifier renaming."
- CWE: N/A

### OMTG-RARE-003: Testing for Jailbreak / Root Detection

Modern smartphone operating systems implement containerization so that each app is restricted to its own sandbox. A regular app cannot access files outside its dedicated data directories, and access to system APIs is restricted via app privileges. As a result, an app’s sensitive data as well as the integrity of the OS is guaranteed under normal conditions. However, when an adversary gains root access to the mobile operating system, the default protections can be bypassed completely.

The risk of malicious code running as root is higher on rooted or jailbroken devices, as some of the default integrity checks are disabled. Developers of apps that handle highly sensitive data (e.g. banking) should therefore consider implementing checks that prevent the app from running under these conditions.

#### Detailed Guides

- [OMTG-RARE-003 Android](0x07a_OMTG-RAREAndroid.md#OMTG-RARE-003)
- [OMTG-RARE-003 iOS](0x07b_OMTG-RARE_iOS.md#OMTG-RARE-003)

#### References

- OWASP MASVS : V8.3: "Verify that the application detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users should be warned, or the app should terminate if the device is rooted."
- CWE : N/A
