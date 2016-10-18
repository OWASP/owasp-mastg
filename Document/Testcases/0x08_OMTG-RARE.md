# Testing Resiliency Against Reverse Engineering

## Overview

This chapter covers defense-in-depth measures that are recommended for apps that process, or give access to, sensitive data or functionality. Lack of any of these controls does not cause a vulnerability - instead, they are meant to increase the app's resiliency against reverse engineering, making it more difficult for adversaries to gain an understanding of the app's internals or extract data from the app.

## Test Cases

### OMTG-RARE-001: Test for Debugging Symbols in Binaries

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.
By default, both ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable. This information is used to resolve references when linking dynamic libraries, and also makes it easier to keep track of the semantics of the code and debugging crashes. It can however be stripped from the release build, unless the goal is to release a dynamic library for public use.

#### Detailed Guides

- [OMTG-DATAST-001 Android](0x00a_OMTG-RARE_Android.md#OMTG-RARE-001)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-RARE_iOS.md#OMTG-DATAST-001)

#### References

- OWASP MASVS: V8-1: "Verify that debugging symbols have been removed from native binaries."
- CWE: N/A

### OMTG-DATAST-009: OMTG-DATAST-009: Test for Meaningful Identifiers in Java Bytecode
[General description]

#### Detailed Guides

- [OMTG-DATAST-009 Android](0x00a_OMTG-RARE_Android.md#OMTG-RARE-002)
- [OMTG-DATAST-009 iOS](0x00b_OMTG-RARE_iOS.md#OMTG-RARE-002)

#### References

- OWASP MASVS: V8-2: "Verify that Java bytecode has been obscured through identifier renaming."
- CWE: N/A
