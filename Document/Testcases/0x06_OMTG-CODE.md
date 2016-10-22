# Testing Code Quality

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-CODE-007: Testing for Secure Compiler Flags
Compilers such as CLANG and GCC support hardening options that add additional runtime security features and checks to the generated executables. While these hardening features don’t fix broken code, they do make exploitation of bugs such as buffer overflows more difficult, and should be activated as a defense-in-depth measure.

This test-case aim to check whether the following Flags are enabled whitin the mobile application's binary :

* Stack smashing protection : 
Stack smashing is the willful use of stack overflows to gain control of a system. There are different buffer overflow protectors available, include Stack Smashing Protector (SSP) for GNU's gcc, ProPolice for IBM's XLC, and Buffer Security Check for Microsoft's Visual compilers (option /GS). 
* PIE support :
Position-independent executables (PIE) are binaries that can be wholly relocated in memory. Building an app with PIE support makes it possible to apply Address Space Layout Randomization (ASLR) during runtime. ASLR aims to make exploitation of memory corruption vulnerabilities more difficult. As of Android 5.0, Android requires all dynamically linked executables to support PIE.
* ARC protection : 
Automatic Reference Counting (ACR) is a compile time protection technique introduced since iOS 5. It provide an additional layer of security at runtime by moving the responsibility of memory management (retains, releases, and autoreleases on Objective-C objects ) from the programmer to the compiler. 


#### Detailed Guides

- [OMTG-CODE-007 Android](0x06a_OMTG-CODE_Android.md#OMTG-CODE-007)
- [OMTG-CODE-007 iOS](0x06b_OMTG-CODE_iOS.md#OMTG-CODE-007)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]
