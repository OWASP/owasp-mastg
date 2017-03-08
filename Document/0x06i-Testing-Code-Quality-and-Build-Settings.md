## Testing Code Quality and Build Settings

### Verifying that the App is Properly Signed

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

#### References

##### OWASP MASVS

- V7.1: "The app is signed and provisioned with valid certificate."

### Testing Whether the App is Debuggable

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

### Verifying that Debugging Symbols Have Been Removed

#### Overview

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.

These symbols can be saved either in "Stabs" format or the DWARF format. When using the Stabs format, debugging symbols, like other symbols, are stored in the regular symbol table. With the DWARF format, debugging symbols are stored in a special "__DWARF" segment within the the binary. DWARF debugging symbols can also be saved a separate debug-information file. In this test case, you verify that no debug symbols are contained in the release binary itself (either in the symbol table, ot the __DWARF segment).

#### Static Analysis

Use gobjdump to inspect the main binary and any included dylibs for Stabs and DWARF symbols.

~~~~
$ gobjdump --stabs --dwarf TargetApp
In archive MyTargetApp:

armv5te:     file format mach-o-arm


aarch64:     file format mach-o-arm64
~~~~

Gobjdump is part of binutils [1] and can be installed via Homebrew.

#### Dynamic Analysis

Not applicable.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [1] https://www.gnu.org/s/binutils/

### Testing for Debugging Code and Verbose Error Logging

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### Testing Exception Handling

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

### Verifying that the App Fails Securely

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### Testing Compiler Settings
Although XCode set all binary security features by default, it still might be relevant to some old application or to check compilation options misconfiguration. The following features are applicable:
* **ARC** - Automatic Reference Counting - memory management feature
  * adds retain and release messages when required
* **Stack Canary** - helps preventing buffer overflow attacks
* **PIE** - Position Independent Executable - enables full ASLR for binary
#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

##### With otool :
Below are examples on how to check for these features. Please note that all of them are enabled in these examples:
* PIE:
~~~
$ unzip DamnVulnerableiOSApp.ipa
$ cd Payload/DamnVulnerableIOSApp.app
$ otool -hv DamnVulnerableIOSApp
DamnVulnerableIOSApp (architecture armv7):
Mach header
magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
MH_MAGIC ARM V7 0x00 EXECUTE 38 4292 NOUNDEFS DYLDLINK TWOLEVEL
WEAK_DEFINES BINDS_TO_WEAK PIE
DamnVulnerableIOSApp (architecture arm64):
Mach header
magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
MH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 38 4856 NOUNDEFS DYLDLINK TWOLEVEL
WEAK_DEFINES BINDS_TO_WEAK PIE
~~~

* Stack Canary:
~~~
$ otool -Iv DamnVulnerableIOSApp | grep stack
0x0046040c 83177 ___stack_chk_fail
0x0046100c 83521 _sigaltstack
0x004fc010 83178 ___stack_chk_guard
0x004fe5c8 83177 ___stack_chk_fail
0x004fe8c8 83521 _sigaltstack
0x00000001004b3fd8 83077 ___stack_chk_fail
0x00000001004b4890 83414 _sigaltstack
0x0000000100590cf0 83078 ___stack_chk_guard
0x00000001005937f8 83077 ___stack_chk_fail
0x0000000100593dc8 83414 _sigaltstack
~~~ 

* Automatic Reference Counting:
~~~
$ otool -Iv DamnVulnerableIOSApp | grep release
0x0045b7dc 83156 ___cxa_guard_release
0x0045fd5c 83414 _objc_autorelease
0x0045fd6c 83415 _objc_autoreleasePoolPop
0x0045fd7c 83416 _objc_autoreleasePoolPush
0x0045fd8c 83417 _objc_autoreleaseReturnValue
0x0045ff0c 83441 _objc_release
[SNIP]
~~~

##### With idb :

IDB automates the process of checking for both stack canary and PIE support. Select the target binary in the IDB gui and click the "Analyze Binary…" button.

![alt tag](Images/Chapters/0x06i/idb.png)

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

### Testing for Memory Management Bugs

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

#### References

##### OWASP MASVS

- V7.7: "In unmanaged code, memory is allocated, freed and used securely."

### Verifying that Java Bytecode Has Been Minifed

Not applicable on iOS.
