### <a name="OMTG-CODE-001"></a>OMTG-CODE-001: Verify that the App is Properly Signed

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

#### References

##### OWASP MASVS

- V7.1: "The app is signed and provisioned with valid certificate."

### <a name="OMTG-CODE-002"></a>OMTG-CODE-002: Test whether the App is Debuggable

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

1. Import the source code into the xCode Editor.
1. Check the project's build settings for 'DEBUG' parameter under "Apple LVM – Preprocessing" -> "Preprocessor Macros".
1. Check the source code for NSAsserts method and its companions.

#### Black-box Testing

This test case should be performed during White-box testing.

#### Remediation

Once you have deployed an iOS application, either through the App Store or as an Ad Hoc or Enterprise build, you won't be able to attach Xcode's debugger to it. To debug problems, you need to analyze Crash Logs and Console output from the device itself. Remove any NSLog calls to prevent debug leakage through the Console.

#### References

(TODO)

### <a name="OMTG-CODE-003"></a>OMTG-CODE-003: Verify that Debugging Symbols Have Been Removed

#### Overview

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.

These symbols can be saved either in "Stabs" format or the DWARF format. When using the Stabs format, debugging symbols, like other symbols, are stored in the regular symbol table. With the DWARF format, debugging symbols are stored in a special "__DWARF" segment within the the binary. DWARF debugging symbols can also be saved a separate debug-information file. In this test case, you verify that no debug symbols are contained in the release binary itself (either in the symbol table, ot the __DWARF segment).

#### Static Analysis

The symbol table can be inspected with the nm tool as follows:

~~~~
$ nm -a TargetApp
TargetApp (for architecture armv7):
         U _ABAddressBookCopyArrayOfAllPeople
         U _ABAddressBookCreateWithOptions
         U _ABAddressBookGetAuthorizationStatus
         U _ABAddressBookRequestAccessWithCompletion
         U _ABMultiValueCopyValueAtIndex
         U _ABMultiValueGetCount
         U _ABMultiValueGetIndexForIdentifier
(...)
~~~~

Stabs symbol entries are denoted with the character '-' [1].

#### Dynamic Analysis

Not applicable.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [1] https://linux.die.net/man/1/nm

### <a name="OMTG-CODE-004"></a>OMTG-CODE-004: Test for Debugging Code and Verbose Error Logging

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-005"></a>OMTG-CODE-005: Test Exception Handling

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

Review the source code to understand/identify who the application handle various types of errors (IPC communications, remote services invokation, etc). Here are some examples of the checks to be performed at this stage :

* Verify that the application use a [well-designed] (https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (an unified) scheme to handle exceptions.
* Verify that the application doesn't expose sensitive information while handeling exceptions, but are still verbose enough to explain the issue to the user. 
* C3

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-006"></a>OMTG-CODE-006: Verify that the App Fails Securely

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-007"></a>OMTG-CODE-007: Test Input Validation

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-008"></a>OMTG-CODE-008: Test Memory Management

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-009"></a>OMTG-CODE-009: Test Compiler Settings

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

##### With otool :

* Check if the stack smashing protection is enabled :

```
$ otool -Iv <app name> | grep stack
```

If the application was compiled with the stack smashing protection two undefined symbols will be present: "___stack_chk_fail" and "___stack_chk_guard".

* Check the PIE protection is enabled :

```
$ otool -Iv <app name> | grep PIE
```

If the above command emit no output then the PIE protection isn't enabled. 

* Check the ACR protection is enabled :

```
$ otool -Iv <app name> | grep _objc_release
```

If the above command emit no output then the ACR protection isn't enabled.

##### With idb :

IDB automates the process of checking for both stack canary and PIE support. Select the target binary in the IDB gui and click the "Analyze Binary…" button.

![alt tag](/Document/Images/Testcases/OMTG-CODE_iOS/idb.png)

#### Remediation

* Stack smashing protection 

Steps for enabling Stack smashing protection within an iOS application:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view its settings.
1. Verify that "–fstack-protector-all" option is selected under "Other C Flags" section.

* PIE support

Steps for building an iOS application as PIE :

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view its settings.
1. For iOS apps, set iOS Deployment Target to iOS 4.3 or later. For Mac apps, set OS X Deployment Target to OS X 10.7 or later.
1. Verify that "Generate Position-Dependent Code" is set at its default value of NO.
1. Verify that Don't "Create Position Independent Executables" is set at its default value of NO.

* ARC protection 

Steps for enabling ACR protection within an iOS application :

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view its settings.
1. Verify that "Objective-C Automatic Reference Counting" is set at its default value of YES.

#### References

* Technical Q&A QA1788 Building a Position Independent Executable : https://developer.apple.com/library/mac/qa/qa1788/_index.html
* idb : https://github.com/dmayer/idb

### <a name="OMTG-CODE-010"></a>OMTG-CODE-010: Verify that Java Bytecode Has Been Minifed

Not applicable on iOS.
