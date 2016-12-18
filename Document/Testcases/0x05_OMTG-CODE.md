# Testing Code Quality and Build Settings

## Overview
The goal of this section is to ensure that basic security coding practices are followed in developing the app, and that "free" security features offered by the compiler are activated.

## Test Cases

### OMTG-CODE-001: Verify the App Signature

#### Detailed Guides

- [OMTG-CODE-001 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-001)
- [OMTG-CODE-001 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-001)

#### References

##### OWASP MASVS

- V7.1: The app is signed and provisioned with valid certificate.

### OMTG-CODE-002: Test Whether the App is Debuggable
Debugging is one of the most powerful dynamic analysis techniques. By attaching a debugger to the running app, it is possible to pause execution at any point and inspect local variables, dump class values, modify values, and generally interact with the program state. Mobile operating systems may differentiate between debug and release builds of an app, and prevent debugging by default unless the app is tagged as a debug build. A a best-practice, debugging should be disabled in a production build.

#### Detailed Guides

- [OMTG-CODE-002 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-002)
- [OMTG-CODE-002 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-002)

#### References

##### OWASP MASVS

- V7.2: "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)."

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-215: Information Exposure Through Debug Information
- CWE-489: Leftover Debug Code


### OMTG-CODE-003: Test For Debugging Symbols in Native Binaries
(todo)

#### Detailed Guides

- [OMTG-CODE-003 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-003)
- [OMTG-CODE-003 iOS](0x5b_OMTG-CODE_iOS.md#OMTG-CODE-003)

#### References

##### OWASP MASVS
* V7.3: Debugging symbols have been removed from native binaries.


### OMTG-CODE-004: Test for Debugging Code in the Release Build
(todo)

#### Detailed Guides

- [OMTG-CODE-004 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-004)
- [OMTG-CODE-004 iOS](0x5b_OMTG-CODE_iOS.md#OMTG-CODE-004)

#### References

##### OWASP MASVS
* V7.4: Debugging code has been removed, and the app does not log verbose errors or debugging messages.


### OMTG-CODE-005-006: Test Exception Handling
Verify that the that mobile app fails safely under all possible expected and unexpected runtime errors, to ensure reliability during execution, and to avoid leaking sensitive data to a malicious third-party application (see : #TODO). 

#### Detailed Guides

- [OMTG-CODE-005 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-005)
- [OMTG-CODE-005 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-005)

#### References

##### OWASP MASVS
* V7.5: The app catches and handles possible exceptions.
* V7.6: Error handling logic in security controls denies access by default.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-636: Not Failing Securely ('Failing Open')
- CWE-391: Unchecked Error Condition

### OMTG-CODE-008: Test Memory Management
(...TODO... Description needs to be rewritten to correctly reflect the requirement).

#### Detailed Guides

- [OMTG-CODE-008 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-008)
- [OMTG-CODE-008 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-008)

##### OWASP MASVS
* V7.8: If the app contains unmanaged code, verify that memory is allocated, freed and used securely.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE


### OMTG-CODE-009: Test Compiler Settings
Compilers such as CLANG and GCC support hardening options that add additional runtime security features and checks to the generated executables. While these hardening features don’t fix broken code, they do make exploitation of bugs such as buffer overflows more difficult, and should be activated as a defense-in-depth measure.

In this phase the tester checks that the following Flags are enabled whitin the mobile application's binary :

* Stack smashing protection : 
When this feature is enabled, a "canary" is placed on the stack to protect the saved base pointer, saved instruction pointer and function arguments. It will be verified upon the function return to see if it has been overwritten.

* PIE support :
Position-independent executables (PIE) are binaries that can be wholly relocated in memory. Building an app with PIE support makes it possible to apply Address Space Layout Randomization (ASLR) during runtime. ASLR aims to make exploitation of memory corruption vulnerabilities more difficult.

* ARC protection : 
Automatic Reference Counting (ACR) is a compile time protection technique introduced since iOS 5. It provide an additional layer of security at runtime by moving the responsibility of memory management (retains, releases, and autoreleases on Objective-C objects ) from the programmer to the compiler. 


#### Detailed Guides

- [OMTG-CODE-009 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-009)
- [OMTG-CODE-009 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-009)

#### References

##### OWASP MASVS
* V7.9: Verify that security features offered by the compiler, such as stack protection, PIE support and automatic reference counting, are activated.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow


