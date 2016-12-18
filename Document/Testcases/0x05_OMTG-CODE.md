# Testing Code Quality

## Overview
The goal of this section is to ensure that basic security coding practices are followed in developing the app, and that "free" security features offered by the compiler are activated.

## Test Cases

### OMTG-CODE-001: Testing for Debug Build 
Debugging is a technique where a hook is attached to a particular application code. Execution pauses once a particular piece of code is reached (break point), giving us the ability to analyze local variables, dump class values, modify values, and generally interact with the program state. A debug build allows therefore an attacker to attach a debugger to the application in order to analyze the behavior during runtime.

#### Detailed Guides

- [OMTG-CODE-001 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-001)
- [OMTG-CODE-001 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-001)

#### References

##### OWASP MASVS: V7: Code quality and build setting requirements
* Verify that all debugging code is removed from the release build, and that the app does log detailed error messages.
* Verify that the app is marked as a release build.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-215: Information Exposure Through Debug Information
- CWE-489: Leftover Debug Code


### OMTG-CODE-002: Testing for Exception Handling
Testing for Exception Handling means verifying that mobile app fails safely under all possible expected and unexpected runtime errors, to ensure reliability during execution, and to avoid leaking sensitive data to a malicious third-party application (see : #TODO). 

#### Detailed Guides

- [OMTG-CODE-002 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-002)
- [OMTG-CODE-002 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-002)

#### References

##### OWASP MASVS: V7: Code quality and build setting requirements
* Verify that the application catches and handles possible exceptions.
* Verify that error handling logic in security controls denies access by default.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-636: Not Failing Securely ('Failing Open')
- CWE-391: Unchecked Error Condition

### OMTG-CODE-003: Testing for Secure Compiler Flags
Compilers such as CLANG and GCC support hardening options that add additional runtime security features and checks to the generated executables. While these hardening features don’t fix broken code, they do make exploitation of bugs such as buffer overflows more difficult, and should be activated as a defense-in-depth measure.

In this phase the tester checks that the following Flags are enabled whitin the mobile application's binary :

* Stack smashing protection : 
When this feature is enabled, a "canary" is placed on the stack to protect the saved base pointer, saved instruction pointer and function arguments. It will be verified upon the function return to see if it has been overwritten.

* PIE support :
Position-independent executables (PIE) are binaries that can be wholly relocated in memory. Building an app with PIE support makes it possible to apply Address Space Layout Randomization (ASLR) during runtime. ASLR aims to make exploitation of memory corruption vulnerabilities more difficult.

* ARC protection : 
Automatic Reference Counting (ACR) is a compile time protection technique introduced since iOS 5. It provide an additional layer of security at runtime by moving the responsibility of memory management (retains, releases, and autoreleases on Objective-C objects ) from the programmer to the compiler. 


#### Detailed Guides

- [OMTG-CODE-003 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-003)
- [OMTG-CODE-003 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-003)

#### References

##### OWASP MASVS: V7: Code quality and build setting requirements
* Verify that security features offered by the compiler, such as stack protection, PIE support and automatic reference counting, are activated.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow

### OMTG-CODE-004: Testing for Unreacheble/Dead code 
Having unreachable code inside an app can be considered as a security risk, as it doesn't reflect the business logic and what the app was initially designed for.

#### Detailed Guides

- [OMTG-CODE-004 Android](0x05a_OMTG-CODE_Android.md#OMTG-CODE-004)
- [OMTG-CODE-004 iOS](0x05b_OMTG-CODE_iOS.md#OMTG-CODE-004)

##### OWASP MASVS: V7: Code quality and build setting requirements
* If the app contains unmanaged code, verify that memory is allocated, freed and used securely.

##### OWASP Mobile Top 10
* M7 - Client Code Quality

##### CWE
* CWE-561: Dead Code
