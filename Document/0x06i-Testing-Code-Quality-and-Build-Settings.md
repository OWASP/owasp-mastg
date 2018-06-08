## Code Quality and Build Settings for iOS Apps

### Making Sure that the App Is Properly Signed

#### Overview

Code signing your app assures users that the app has a known source and hasn't been modified since it was last signed. Before your app can integrate app services, be installed on a device, or be submitted to the App Store, it must be signed with a certificate issued by Apple. For more information on how to request certificates and code sign your apps, review the [App Distribution Guide.](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html "App Distribution Guide")

You can retrieve the signing certificate information from the application's .app file with [codesign.](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/codesign.1.html) Codesign is used to create, check, and display code signatures, as well as inquire into the dynamic status of signed code in the system.

After you get the application's .ipa file, re-save it as a ZIP file and decompress the ZIP file. Navigate to the Payload directory, where the application's .app file will be.

Execute the following `codesign` command:

```sh
$ codesign -dvvv <yourapp.app>
Executable=/Users/Documents/<yourname>/Payload/<yourname.app>/<yourname>
Identifier=com.example.example
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=455758418a5f6a878bb8fdb709ccfca52c0b5b9e
CandidateCDHash sha256=fd44efd7d03fb03563b90037f92b6ffff3270c46
Hash choices=sha1,sha256
CDHash=fd44efd7d03fb03563b90037f92b6ffff3270c46
Signature size=4678
Authority=iPhone Distribution: Example Ltd
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=4 Aug 2017, 12:42:52
Info.plist entries=66
TeamIdentifier=8LAMR92KJ8
Sealed Resources version=2 rules=12 files=1410
Internal requirements count=1 size=176
```

### Finding Debugging Symbols

#### Overview

Generally, as little explanatory information as possible should be provided with the compiled code. Some metadata (such as debugging information, line numbers, and descriptive function or method names) makes the binary or byte-code easier for the reverse engineer to understand but isn't necessary in a release build. This metadata can therefore be discarded without impacting the app's functionality.

These symbols can be saved in "Stabs" format or the DWARF format. In the Stabs format, debugging symbols, like other symbols, are stored in the regular symbol table. In the DWARF format, debugging symbols are stored in a special "\_\_DWARF" segment within the binary. DWARF debugging symbols can also be saved as a separate debug-information file. In this test case, you make sure that no debug symbols are contained in the release binary itself (in neither the symbol table nor the \_\_DWARF segment).

#### Static Analysis

Use gobjdump to inspect the main binary and any included dylibs for Stabs and DWARF symbols.

```
$ gobjdump --stabs --dwarf TargetApp
In archive MyTargetApp:

armv5te:     file format mach-o-arm

aarch64:     file format mach-o-arm64
```

Gobjdump is part of [binutils](https://www.gnu.org/s/binutils/ "Binutils") and can be installed on macOS via Homebrew.

#### Dynamic Analysis

Dynamic analysis is not applicable for finding debugging symbols.

#### Remediation

Make sure that debugging symbols are stripped when the application is being built for production. Stripping debugging symbols will reduce the size of the binary and increase the difficulty of reverse engineering. To strip debugging symbols, set `Strip Debug Symbols During Copy` to "YES" via the project's build settings.

A proper [Crash Reporter System](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AnalyzingCrashReports/AnalyzingCrashReports.html) is possible because the system doesn't require any symbols in the application binary.

### Finding Debugging Code and Verbose Error Logging

#### Overview

To speed up verification and get a better understanding of errors, developers often include debugging code, such as verbose logging statements (using `NSLog`, `println`, `print`, `dump`, and `debugPrint`) about responses from their APIs and about their application's progress and/or state. Furthermore, there may be debugging code for "management-functionality," which is used by developers to set the application's state or mock responses from an API. Reverse engineers can easily use this information to track what's happening with the application. Therefore, debugging code should be removed from the application's release version.

#### Static Analysis

You can take the following static analysis approach for the logging statements:

1.	Import the application's code into Xcode.
2.	Search the code for the following printing functions: `NSLog`, `println`, `print`, `dump`, `debugPrint`.
3.	When you find one of them, determine whether the developers used a wrapping function around the logging function for better mark up of the statements to be logged; if so, add that function to your search.
4.	For every result of steps 2 and 3, determine whether macros or debug-state related guards have been set to turn the logging off in the release build. Please note the change in how Objective-C can use preprocessor macros:

```objc
#ifdef DEBUG
    // Debug-only code
#endif
```

The procedure for enabling this behavior in Swift has changed: you need to either set environment variables in your scheme or set them as custom flags in the target's build settings. Please note that the following functions (which allow you to determine whether the app was built in the Swift 2.1. release-configuration) aren't recommended, as Xcode 8 and Swift 3 don't support these functions:

-	`_isDebugAssertConfiguration`
-	`_isReleaseAssertConfiguration`
-	`_isFastAssertConfiguration`.

Depending on the application's setup, there may be more logging functions. For example, when [CocoaLumberjack](https://github.com/CocoaLumberjack/CocoaLumberjack "CocoaLumberjack") is used, static analysis is a bit different.

For the "debug-management" code (which is built-in): inspect the storyboards to see whether there are any flows and/or view-controllers that provide functionality different from the functionality the application should support. This functionality can be anything from debug views to printed error messages, from custom stub-response configurations to logs written to files on the application's file system or a remote server.

#### Dynamic Analysis

Dynamic analysis should be executed on both a simulator and a device because developers sometimes use target-based functions (instead of functions based on a release/debug-mode) to execute the debugging code.
1.	Run the application on a simulator and check for output in the console during the app's execution.
2.	 Attach a device to your Mac, run the application on the device via Xcode, and check for output in the console during the app's execution in the console.

For the other "manager-based" debug code: click through the application on both a simulator and a device to see if you can find any functionality that allows an app's profiles to be pre-set, allows the actual server to be selected or allows responses from the API to be selected.

#### Remediation

As a developer, incorporating debug statements into your application's debug version should not be a problem if you realize that the debugging statements should never
1.	be present in the application's release version or
2.	end up in the application's release configuration.

In Objective-C, developers can use preprocessor macros to filter out debug code:

```objc
#ifdef DEBUG
    // Debug-only code
#endif
```

In Swift 2 (with Xcode 7), you have to set custom compiler flags for every target, and compiler flags have to start with "-D." So you can use the following annotations when the debug flag `DMSTG-DEBUG` is set:

```swift
#if MSTG-DEBUG
    // Debug-only code
#endif
```

In Swift 3 (with Xcode 8), you can set Active Compilation Conditions in Build settings/Swift compiler - Custom flags. Instead of a preprocessor, Swift 3 uses [conditional compilation blocks](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34 "Swift conditional compilation blocks") based on the defined conditions:

```swift
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

### Testing Exception Handling

#### Overview

Exceptions often occur after an application enters an abnormal or erroneous state.
Testing exception handling is about making sure that the application will handle the exception and get into a safe state without exposing any sensitive information via its logging mechanisms or the UI.

Bear in mind that exception handling in Objective-C is quite different from exception handling in Swift. Bridging the two approaches in an application that is written in both legacy Objective-C code and Swift code can be problematic.

##### Exception handling in Objective-C

Objective-C has two types of errors:

**NSException**
`NSException` is used to handle programming and low-level errors (e.g., division by 0 and out-of-bounds array access).
An `NSException` can either be raised by `raise` or thrown with `@throw`. Unless caught, this exception will invoke the unhandled exception handler, with which you can log the statement (logging will halt the program). `@catch` allows you to recover from the exception if you're using a `@try`-`@catch`-block:

```obj-c
 @try {
 	//do work here
 }

@catch (NSException *e) {
	//recover from exception
}

@finally {
 	//cleanup
```

Bear in mind that using `NSException` comes with memory management pitfalls: you need to [clean up allocations](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/RaisingExceptions.html#//apple_ref/doc/uid/20000058-BBCCFIBF "Raising exceptions") from the try block that are in the [finally block](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/HandlingExceptions.html "Handling Exceptions"). Note that you can promote `NSException` objects to `NSError` by instantiating an `NSError` in the `@catch` block.

**NSError**
`NSError` is used for all other types of [errors](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html "Dealing with Errors"). Some Cocoa framework APIs provide errors as objects in their failure callback in case something goes wrong; those that don't provide them pass a pointer to an `NSError` object by reference. It is a good practice to provide a `BOOL` return type to the method that takes a pointer to an `NSError` object to indicate success or failure. If there's a return type, make sure to return "nil" for errors. If "NO" or "nil" is returned, it allows you to inspect the error/reason for failure.

##### Exception Handling in Swift

Exception handing in Swift (2 - 4) is quite different. The try-catch block is not there to handle `NSException`. The block is used to handle errors that conform to the `Error` (Swift 3) or `ErrorType` (Swift 2) protocol. This can be challenging when Objective-C and Swift code are combined in an application. Therefore, `NSError` is preferable to `NSException` for programs written in both languages. Furthermore, error-handling is opt-in in Objective-C, but `throws` must be explicitly handled in Swift. To convert error-throwing, look at the [Apple documentation](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns").
Methods that can throw errors use the `throws` keyword. There are four ways to [handle errors in Swift](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html "Error Handling in Swift"):  

- Propagate the error from a function to the code that calls that function. In this situation, there's no `do-catch`; there's only a `throw` throwing the actual error or a `try` to execute the method that throws. The method containing the `try` also requires the `throws` keyword:

```swift
func dosomething(argumentx:TypeX) throws {
	try functionThatThrows(argumentx: argumentx)
}
```
- Handle the error with a `do-catch` statement. You can use the following pattern:

```swift
do {
    try functionThatThrows()
    defer {
    	//use this as your finally block as with Objective-c
    }
    statements
} catch pattern 1 {
    statements
} catch pattern 2 where condition {
    statements
}
```

- Handle the error as an optional value:

```swift
	let x = try? functionThatThrows()
	//In this case the value of x is nil in case of an error.
```  
- Use the `try!` expression to assert that the error won't occur.

#### Static Analysis

Review the source code to understand how the application handles various types of errors (IPC communications, remote services invocation, etc.). The following sections list examples of what you should check for each language at this stage.

##### Static Analysis in Objective-C

Make sure that

- the application uses a well-designed and unified scheme to handle exceptions and errors,
- the Cocoa framework exceptions are handled correctly,
- the allocated memory in the `@try` blocks is released in the `@finally` blocks,
- for every `@throw`, the calling method has a proper `@catch` at the level of either the calling method or the `NSApplication`/`UIApplication` objects to clean up sensitive information and possibly recover,
- the application doesn't expose sensitive information while handling errors in its UI or in its log statements, and the statements are verbose enough to explain the issue to the user,
- high-risk applications' confidential information, such as keying material and authentication information, is always wiped during the execution of `@finally` blocks,
- `raise` is rarely used (it's used when the program must be terminated without further warning),
- `NSError` objects don't contain data that might leak sensitive information.

##### Static Analysis in Swift

Make sure that

- the application uses a well-designed and unified scheme to handle errors,
- the application doesn't expose sensitive information while handling errors in its UI or in its log statements, and the statements are verbose enough to explain the issue to the user,
- high-risk applications' confidential information, such as keying material and authentication information, is always wiped during the execution of `defer` blocks,
- `try!` is used only with proper guarding up front (to programmatically verify that the method that's called with `try!` can't throw an error).

#### Dynamic Testing

There are several dynamic analysis methods:

- Enter unexpected values in the iOS application's UI fields.
- Test the custom URL schemes, pasteboard, and other inter-app communication controls by providing unexpected or exception-raising values.
- Tamper with the network communication and/or the files stored by the application.
- For Objective-C, you can use Cycript to hook into methods and provide them arguments that may cause the callee to throw an exception.

In most cases, the application should not crash. Instead, it should

- recover from the error or enter a state from which it can inform the user that it can't continue,
- provide a message (which shouldn't leak sensitive information) to get the user to take appropriate action,
- withhold information from the application's logging mechanisms.

#### Remediation

Developers can implement proper error handling in several ways:

- Make sure that the application uses a well-designed and unified scheme to handle errors.
- Make sure that all logging is removed or guarded as described in the test case "Testing for Debugging Code and Verbose Error Logging."
- For a high-risk application written in Objective-C: create an exception handler that  removes secrets that shouldn't be easily retrievable. The handler can be set via `NSSetUncaughtExceptionHandler`.
- Refrain from using `try!` in Swift unless you're certain that there's no error in the throwing method that's being called.
- Make sure that the Swift error doesn't propagate into too many intermediate methods.


### Make Sure That Free Security Features Are Activated

#### Overview

Although Xcode enables all binary security features by default, it may be relevant to verify this for an old application or to check for the misconfiguration of compilation options. The following features are applicable:

-	**ARC** - Automatic Reference Counting - memory management feature
	-	adds retain and release messages when required
-	**Stack Canary** - helps prevent buffer overflow attacks
-	**PIE** - Position Independent Executable - enables full ASLR for binary

#### Static Analysis

##### Xcode Project Settings

- Stack-smashing protection

Steps for enabling Stack-smashing protection in an iOS application:

1.	In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2.	Make sure that the "-fstack-protector-all" option is selected in the "Other C Flags" section.

3.	Make sure that Position Independent Executables (PIE) support is enabled.

Steps for building an iOS application as PIE:

1.	In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2.	Set the iOS Deployment Target to iOS 4.3 or later.
3.	Make sure that "Generate Position-Dependent Code" is set to its default value ("NO").
4.	Make sure that "Don't Create Position Independent Executables" is set to its default value ("NO").

- ARC protection

Steps for enabling ACR protection for an iOS application:

1.	In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2.	Make sure that "Objective-C Automatic Reference Counting" is set to its default value ("YES").

See the [Technical Q&A QA1788 Building a Position Independent Executable]( https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable").

##### With otool

Below are procedures for checking the binary security features described above. All the features are enabled in these examples.

-   PIE:

```shell
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
```

-   stack canary:

```shell
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
```

-   Automatic Reference Counting:

```shell
$ otool -Iv DamnVulnerableIOSApp | grep release
0x0045b7dc 83156 ___cxa_guard_release
0x0045fd5c 83414 _objc_autorelease
0x0045fd6c 83415 _objc_autoreleasePoolPop
0x0045fd7c 83416 _objc_autoreleasePoolPush
0x0045fd8c 83417 _objc_autoreleaseReturnValue
0x0045ff0c 83441 _objc_release
[SNIP]
```

##### With idb

IDB automates the processes of checking for stack canary and PIE support. Select the target binary in the IDB GUI and click the "Analyze Binary…" button.

![alt tag](Images/Chapters/0x06i/idb.png)

### References

#### OWASP Mobile Top 10 2016

-	M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V7.1: "The app is signed and provisioned with a valid certificate."
- V7.4: "Debugging code has been removed, and the app does not log verbose errors or debugging messages."
- V7.6: "The app catches and handles possible exceptions."
- V7.7: "Error handling logic in security controls denies access by default."
- V7.9: "Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated."

#### Tools

- idb - https://github.com/dmayer/idb
- Codesign - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/codesign.1.html
