# iOS Code Quality and Build Settings

## Making Sure that the App Is Properly Signed (MSTG-CODE-1)

### Overview

Code signing your app assures users that the app has a known source and hasn't been modified since it was last signed. Before your app can integrate app services, be installed on a device, or be submitted to the App Store, it must be signed with a certificate issued by Apple. For more information on how to request certificates and code sign your apps, review the [App Distribution Guide.](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html "App Distribution Guide")

You can retrieve the signing certificate information from the application's .app file with [codesign](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html "Code Signing Tasks"). Codesign is used to create, check, and display code signatures, as well as inquire into the dynamic status of signed code in the system.

After you get the application's IPA file, re-save it as a ZIP file and decompress the ZIP file. Navigate to the Payload directory, where the application's .app file will be.

Execute the following `codesign` command to display the signing information:

```bash
$ codesign -dvvv YOURAPP.app
Executable=/Users/Documents/YOURAPP/Payload/YOURAPP.app/YOURNAME
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

There are various ways to distribute your app as described at [the Apple documentation](https://developer.apple.com/business/distribute/ "Apple Business"), which include using the App Store or via Apple Business Manager for custom or in-house distribution. In case of an in-house distribution scheme, make sure that no ad hoc certificates are used when the app is signed for distribution.

## Determining Whether the App is Debuggable (MSTG-CODE-2)

### Overview

Debugging iOS applications can be done using Xcode, which embeds a powerful debugger called lldb. Lldb is the default debugger since Xcode5 where it replaced GNU tools like gdb and is fully integrated in the development environment. While debugging is a useful feature when developing an app, it has to be turned off before releasing apps to the App Store or within an enterprise program.

Generating an app in Build or Release mode depends on build settings in Xcode; when an app is generated in Debug mode, a DEBUG flag is inserted in the generated files.

### Static Analysis

At first you need to determine the mode in which your app is to be generated to check the flags in the environment:

- Select the build settings of the project
- Under 'Apple LVM - Preprocessing' and 'Preprocessor Macros', make sure 'DEBUG' or 'DEBUG_MODE' is not selected (Objective-C)
- Make sure that the "Debug executable" option is not selected.
- Or in the 'Swift Compiler - Custom Flags' section / 'Other Swift Flags', make sure the '-D DEBUG' entry does not exist.

### Dynamic Analysis

Check whether you can attach a debugger directly, using Xcode. Next, check if you can debug the app on a jailbroken device after Clutching it. This is done using the debug-server which comes from the BigBoss repository at Cydia.

Note: if the application is equipped with anti-reverse engineering controls, then the debugger can be detected and stopped.

## Finding Debugging Symbols (MSTG-CODE-3)

### Overview

Generally, as little explanatory information as possible should be provided with the compiled code. Some metadata (such as debugging information, line numbers, and descriptive function or method names) makes the binary or byte-code easier for the reverse engineer to understand but isn't necessary in a release build. This metadata can therefore be discarded without impacting the app's functionality.

These symbols can be saved in "Stabs" format or the DWARF format. In the Stabs format, debugging symbols, like other symbols, are stored in the regular symbol table. In the DWARF format, debugging symbols are stored in a special "\_\_DWARF" segment within the binary. DWARF debugging symbols can also be saved as a separate debug-information file. In this test case, you make sure that no debug symbols are contained in the release binary itself (in neither the symbol table nor the \_\_DWARF segment).

### Static Analysis

Use gobjdump to inspect the main binary and any included dylibs for Stabs and DWARF symbols.

```bash
$ gobjdump --stabs --dwarf TargetApp
In archive MyTargetApp:

armv5te:     file format mach-o-arm

aarch64:     file format mach-o-arm64
```

Gobjdump is part of [binutils](https://www.gnu.org/s/binutils/ "Binutils") and can be installed on macOS via Homebrew.

Make sure that debugging symbols are stripped when the application is being built for production. Stripping debugging symbols will reduce the size of the binary and increase the difficulty of reverse engineering. To strip debugging symbols, set `Strip Debug Symbols During Copy` to `YES` via the project's build settings.

A proper [Crash Reporter System](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AnalyzingCrashReports/AnalyzingCrashReports.html "Crash Reporter System") is possible because the system doesn't require any symbols in the application binary.

### Dynamic Analysis

Dynamic analysis is not applicable for finding debugging symbols.

## Finding Debugging Code and Verbose Error Logging (MSTG-CODE-4)

### Overview

To speed up verification and get a better understanding of errors, developers often include debugging code, such as verbose logging statements (using `NSLog`, `println`, `print`, `dump`, and `debugPrint`) about responses from their APIs and about their application's progress and/or state. Furthermore, there may be debugging code for "management-functionality", which is used by developers to set the application's state or mock responses from an API. Reverse engineers can easily use this information to track what's happening with the application. Therefore, debugging code should be removed from the application's release version.

### Static Analysis

You can take the following static analysis approach for the logging statements:

1. Import the application's code into Xcode.
2. Search the code for the following printing functions: `NSLog`, `println`, `print`, `dump`, `debugPrint`.
3. When you find one of them, determine whether the developers used a wrapping function around the logging function for better mark up of the statements to be logged; if so, add that function to your search.
4. For every result of steps 2 and 3, determine whether macros or debug-state related guards have been set to turn the logging off in the release build. Please note the change in how Objective-C can use preprocessor macros:

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

The procedure for enabling this behavior in Swift has changed: you need to either set environment variables in your scheme or set them as custom flags in the target's build settings. Please note that the following functions (which allow you to determine whether the app was built in the Swift 2.1. release-configuration) aren't recommended, as Xcode 8 and Swift 3 don't support these functions:

- `_isDebugAssertConfiguration`
- `_isReleaseAssertConfiguration`
- `_isFastAssertConfiguration`.

Depending on the application's setup, there may be more logging functions. For example, when [CocoaLumberjack](https://github.com/CocoaLumberjack/CocoaLumberjack "CocoaLumberjack") is used, static analysis is a bit different.

For the "debug-management" code (which is built-in): inspect the storyboards to see whether there are any flows and/or view-controllers that provide functionality different from the functionality the application should support. This functionality can be anything from debug views to printed error messages, from custom stub-response configurations to logs written to files on the application's file system or a remote server.

As a developer, incorporating debug statements into your application's debug version should not be a problem as long as you make sure that the debug statements are never present in the application's release version.

In Objective-C, developers can use preprocessor macros to filter out debug code:

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

In Swift 2 (with Xcode 7), you have to set custom compiler flags for every target, and compiler flags have to start with "-D". So you can use the following annotations when the debug flag `DMSTG-DEBUG` is set:

```default
#if MSTG-DEBUG
    // Debug-only code
#endif
```

In Swift 3 (with Xcode 8), you can set Active Compilation Conditions in Build settings/Swift compiler - Custom flags. Instead of a preprocessor, Swift 3 uses [conditional compilation blocks](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34 "Swift conditional compilation blocks") based on the defined conditions:

```default
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

### Dynamic Analysis

Dynamic analysis should be executed on both a simulator and a device because developers sometimes use target-based functions (instead of functions based on a release/debug-mode) to execute the debugging code.

1. Run the application on a simulator and check for output in the console during the app's execution.
2. Attach a device to your Mac, run the application on the device via Xcode, and check for output in the console during the app's execution in the console.

For the other "manager-based" debug code: click through the application on both a simulator and a device to see if you can find any functionality that allows an app's profiles to be pre-set, allows the actual server to be selected or allows responses from the API to be selected.

## Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)

### Overview

iOS applications often make use of third party libraries which accelerate development as the developer has to write less code in order to solve a problem. However, third party libraries may contain vulnerabilities, incompatible licensing, or malicious content. Additionally, it is difficult for organizations and developers to manage application dependencies, including monitoring library releases and applying available security patches.

There are three widely used package management tools [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org"), [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub"), and [CocoaPods](https://cocoapods.org "CocoaPods.org"):

- The Swift Package Manager is open source, included with the Swift language, integrated into Xcode (since Xcode 11) and supports [Swift, Objective-C, Objective-C++, C, and C++](https://developer.apple.com/documentation/swift_packages "Swift Packages Documentation") packages. It is written in Swift, decentralized and uses the Package.swift file to document and manage project dependencies.
- Carthage is open source and can be used for Swift and Objective-C packages. It is written in Swift, decentralized and uses the Cartfile file to document and manage project dependencies.
- CocoaPods is open source and can be used for Swift and Objective-C packages. It is written in Ruby, utilizes a centralized package registry for public and private packages and uses the Podfile file to document and manage project dependencies.

There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `OHHTTPStubs` used for testing.
- Libraries that are packed within the actual production application, such as `Alamofire`.

These libraries can lead to unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example is `AFNetworking` version 2.5.1, which contained a bug that disabled certificate validation. This vulnerability would allow attackers to execute man-in-the-middle attacks against apps that are using the library to connect to their APIs.
- A library can no longer be maintained or hardly be used, which is why no vulnerabilities are reported and/or fixed. This can lead to having bad and/or vulnerable code in your application through the library.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its source code. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.

### Static Analysis

#### Detecting vulnerabilities of third party libraries

In order to ensure that the libraries used by the apps are not carrying vulnerabilities, one can best check the dependencies installed by CocoaPods or Carthage.

##### Swift Package Manager

In case [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org") is used for managing third party dependencies, the following steps can be taken to analyze the third party libraries for vulnerabilities:

First, at the root of the project, where the Package.swift file is located, type

```bash
$ swift build
```

Next, check the file Package.resolved for the actual versions used and inspect the given libraries for known vulnerabilities.

You can utilize the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check")'s experimental [Swift Package Manager Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html "dependency-check – SWIFT Package Manager Analyzer") to identify the [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") naming scheme of all dependencies and any corresponding [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") entries. Scan the application's Package.swift file and generate a report of known vulnerable libraries with the following command:

```bash
$ dependency-check  --enableExperimental --out . --scan Package.swift
```

##### CocoaPods

In case [CocoaPods](https://cocoapods.org "CocoaPods.org") is used for managing third party dependencies, the following steps can be taken to analyze the third party libraries for vulnerabilities.

First, at the root of the project, where the Podfile is located, execute the following commands:

```bash
$ sudo gem install CocoaPods
$ pod install
```

Next, now that the dependency tree has been built, you can create an overview of the dependencies and their versions by running the following commands:

```bash
$ sudo gem install cocoapods-dependencies
$ pod dependencies
```

The result of the steps above can now be used as input for searching different vulnerability feeds for known vulnerabilities.

> Note:
>
> 1. If the developer packs all dependencies in terms of its own support library using a .podspec file, then this .podspec file can be checked with the experimental CocoaPods podspec checker.
> 2. If the project uses CocoaPods in combination with Objective-C, SourceClear can be used.
> 3. Using CocoaPods with HTTP-based links instead of HTTPS might allow for man-in-the-middle attacks during the download of the dependency, allowing an attacker to replace (parts of) the library with other content. Therefore, always use HTTPS.

You can utilize the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check")'s experimental [CocoaPods Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html "dependency-check – CocoaPods Analyzer")
to identify the [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") naming scheme of all dependencies and any corresponding [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") entries. Scan the application's \*.podspec and/or Podfile.lock files and generate a report of known vulnerable libraries with the following command:

```bash
$ dependency-check  --enableExperimental --out . --scan Podfile.lock
```

##### Carthage

In case [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub") is used for third party dependencies, then the following steps can be taken to analyze the third party libraries for vulnerabilities.

First, at the root of the project, where the Cartfile is located, type

```bash
$ brew install carthage
$ carthage update --platform iOS
```

Next, check the Cartfile.resolved for actual versions used and inspect the given libraries for known vulnerabilities.

> Note, at the time of writing this chapter, there is no automated support for Carthage based dependency analysis known to the authors.

##### Discovered library vulnerabilities

When a library is found to contain vulnerabilities, then the following reasoning applies:

- Is the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched. If not, check whether the vulnerability actually affects the application. If that is the case or might be the case in the future, then look for an alternative which provides similar functionality, but without the vulnerabilities.
- Is the library not packaged with the application? See if there is a patched version in which the vulnerability is fixed. If this is not the case, check if the implications of the vulnerability for the build process. Could the vulnerability impede a build or weaken the security of the build-pipeline? Then try looking for an alternative in which the vulnerability is fixed.

In case frameworks are added manually as linked libraries:

1. Open the xcodeproj file and check the project properties.
2. Go to the tab **Build Phases** and check the entries in **Link Binary With Libraries** for any of the libraries. See earlier sections on how to obtain similar information using [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "MobSF").

In the case of copy-pasted sources: search the header files (in case of using Objective-C) and otherwise the Swift files for known method names for known libraries.

Next, note that for hybrid applications, you will have to check the JavaScript dependencies with RetireJS. Similarly for Xamarin, you will have to check the C# dependencies.

Last, if the application is a high-risk application, you will end up vetting the library manually. In that case there are specific requirements for native code, which are similar to the requirements established by the MASVS for the application as a whole. Next to that, it is good to vet whether all best practices for software engineering are applied.

#### Detecting the Licenses Used by the Libraries of the Application

In order to ensure that the copyright laws are not infringed, one can best check the dependencies installed by Swift Packager Manager, CocoaPods, or Carthage.

##### Swift Package Manager

When the application sources are available and Swift Package Manager is used, execute the following code in the root directory of the project, where the Package.swift file is located:

```bash
$ swift build
```

The sources of each of the dependencies have now been downloaded to `/.build/checkouts/` folder in the project. Here you can find the license for each of the libraries in their respective folder.

##### CocoaPods

When the application sources are available and CocoaPods is used, then execute the following steps to get the different licenses:
First, at the root of the project, where the Podfile is located, type

```bash
$ sudo gem install CocoaPods
$ pod install
```

This will create a Pods folder where all libraries are installed, each in their own folder. You can now check the licenses for each of the libraries by inspecting the license files in each of the folders.

##### Carthage

When the application sources are available and Carthage is used, execute the following code in the root directory of the project, where the Cartfile is located:

```bash
$ brew install carthage
$ carthage update --platform iOS
```

The sources of each of the dependencies have now been downloaded to `Carthage/Checkouts` folder in the project. Here you can find the license for each of the libraries in their respective folder.

##### Issues with library licenses

When a library contains a license in which the app's IP needs to be open-sourced, check if there is an alternative for the library which can be used to provide similar functionalities.

Note: In case of a hybrid app, please check the build-tools used: most of them do have a license enumeration plugin to find the licenses being used.

### Dynamic Analysis

The dynamic analysis of this section comprises of two parts: the actual license verification and checking which libraries are involved in case of missing sources.

It need to be validated whether the copyrights of the licenses have been adhered to. This often means that the application should have an `about` or `EULA` section in which the copy-right statements are noted as required by the license of the third party library.

When no source-code is available for library analysis, you can find some of the frameworks being used with otool and MobSF.
After you obtain the library and Clutched it (e.g. removed the DRM), you can run oTool with the root of the application's directory:

```bash
$ otool -L <Executable>
```

However, these do not include all the libraries being used. Next, with class-dump (for Objective-C) or the more recent dsdump you can generate a subset of the header files used and derive which libraries are involved. But not detect the version of the library.

```bash
$ ./class-dump <Executable> -r
```

## Testing Exception Handling (MSTG-CODE-6)

### Overview

Exceptions often occur after an application enters an abnormal or erroneous state.
Testing exception handling is about making sure that the application will handle the exception and get into a safe state without exposing any sensitive information via its logging mechanisms or the UI.

Bear in mind that exception handling in Objective-C is quite different from exception handling in Swift. Bridging the two approaches in an application that is written in both legacy Objective-C code and Swift code can be problematic.

#### Exception handling in Objective-C

Objective-C has two types of errors:

**NSException**
`NSException` is used to handle programming and low-level errors (e.g., division by 0 and out-of-bounds array access).
An `NSException` can either be raised by `raise` or thrown with `@throw`. Unless caught, this exception will invoke the unhandled exception handler, with which you can log the statement (logging will halt the program). `@catch` allows you to recover from the exception if you're using a `@try`-`@catch`-block:

```objectivec
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
`NSError` is used for all other types of [errors](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html "Dealing with Errors"). Some Cocoa framework APIs provide errors as objects in their failure callback in case something goes wrong; those that don't provide them pass a pointer to an `NSError` object by reference. It is a good practice to provide a `BOOL` return type to the method that takes a pointer to an `NSError` object to indicate success or failure. If there's a return type, make sure to return `nil` for errors. If `NO` or `nil` is returned, it allows you to inspect the error/reason for failure.

#### Exception Handling in Swift

Exception handing in Swift (2 - 5) is quite different. The try-catch block is not there to handle `NSException`. The block is used to handle errors that conform to the `Error` (Swift 3) or `ErrorType` (Swift 2) protocol. This can be challenging when Objective-C and Swift code are combined in an application. Therefore, `NSError` is preferable to `NSException` for programs written in both languages. Furthermore, error-handling is opt-in in Objective-C, but `throws` must be explicitly handled in Swift. To convert error-throwing, look at the [Apple documentation](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns").
Methods that can throw errors use the `throws` keyword. The `Result` type represents a success or failure, see [Result](https://developer.apple.com/documentation/swift/result), [How to use Result in Swift 5](https://www.hackingwithswift.com/articles/161/how-to-use-result-in-swift) and [The power of Result types in Swift](https://www.swiftbysundell.com/posts/the-power-of-result-types-in-swift). There are four ways to [handle errors in Swift](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html "Error Handling in Swift"):

- Propagate the error from a function to the code that calls that function. In this situation, there's no `do-catch`; there's only a `throw` throwing the actual error or a `try` to execute the method that throws. The method containing the `try` also requires the `throws` keyword:

```default
func dosomething(argumentx:TypeX) throws {
    try functionThatThrows(argumentx: argumentx)
}
```

- Handle the error with a `do-catch` statement. You can use the following pattern:

  ```default
  func doTryExample() {
      do {
          try functionThatThrows(number: 203)
      } catch NumberError.lessThanZero {
          // Handle number is less than zero
      } catch let NumberError.tooLarge(delta) {
          // Handle number is too large (with delta value)
      } catch {
          // Handle any other errors
      }
  }

  enum NumberError: Error {
      case lessThanZero
      case tooLarge(Int)
      case tooSmall(Int)
  }

  func functionThatThrows(number: Int) throws -> Bool {
      if number < 0 {
          throw NumberError.lessThanZero
      } else if number < 10 {
          throw NumberError.tooSmall(10 - number)
      } else if number > 100 {
          throw NumberError.tooLarge(100 - number)
      } else {
          return true
      }
  }
  ```

- Handle the error as an optional value:

  ```default
      let x = try? functionThatThrows()
      // In this case the value of x is nil in case of an error.
  ```

- Use the `try!` expression to assert that the error won't occur.
- Handle the generic error as a `Result` return:

```default
enum ErrorType: Error {
    case typeOne
    case typeTwo
}

func functionWithResult(param: String?) -> Result<String, ErrorType> {
    guard let value = param else {
        return .failure(.typeOne)
    }
    return .success(value)
}

func callResultFunction() {
    let result = functionWithResult(param: "OWASP")

    switch result {
    case let .success(value):
        // Handle success
    case let .failure(error):
        // Handle failure (with error)
    }
}
```

- Handle network and JSON decoding errors with a `Result` type:

```default
struct MSTG: Codable {
    var root: String
    var plugins: [String]
    var structure: MSTGStructure
    var title: String
    var language: String
    var description: String
}

struct MSTGStructure: Codable {
    var readme: String
}

enum RequestError: Error {
    case requestError(Error)
    case noData
    case jsonError
}

func getMSTGInfo() {
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/owasp-mstg/master/book.json") else {
        return
    }

    request(url: url) { result in
        switch result {
        case let .success(data):
            // Handle success with MSTG data
            let mstgTitle = data.title
            let mstgDescription = data.description
        case let .failure(error):
            // Handle failure
            switch error {
            case let .requestError(error):
                // Handle request error (with error)
            case .noData:
                // Handle no data received in response
            case .jsonError:
                // Handle error parsing JSON
            }
        }
    }
}

func request(url: URL, completion: @escaping (Result<MSTG, RequestError>) -> Void) {
    let task = URLSession.shared.dataTask(with: url) { data, _, error in
        if let error = error {
            return completion(.failure(.requestError(error)))
        } else {
            if let data = data {
                let decoder = JSONDecoder()
                guard let response = try? decoder.decode(MSTG.self, from: data) else {
                    return completion(.failure(.jsonError))
                }
                return completion(.success(response))
            }
        }
    }
    task.resume()
}
```

### Static Analysis

Review the source code to understand how the application handles various types of errors (IPC communications, remote services invocation, etc.). The following sections list examples of what you should check for each language at this stage.

#### Static Analysis in Objective-C

Make sure that

- the application uses a well-designed and unified scheme to handle exceptions and errors,
- the Cocoa framework exceptions are handled correctly,
- the allocated memory in the `@try` blocks is released in the `@finally` blocks,
- for every `@throw`, the calling method has a proper `@catch` at the level of either the calling method or the `NSApplication`/`UIApplication` objects to clean up sensitive information and possibly recover,
- the application doesn't expose sensitive information while handling errors in its UI or in its log statements, and the statements are verbose enough to explain the issue to the user,
- high-risk applications' confidential information, such as keying material and authentication information, is always wiped during the execution of `@finally` blocks,
- `raise` is rarely used (it's used when the program must be terminated without further warning),
- `NSError` objects don't contain data that might leak sensitive information.

#### Static Analysis in Swift

Make sure that

- the application uses a well-designed and unified scheme to handle errors,
- the application doesn't expose sensitive information while handling errors in its UI or in its log statements, and the statements are verbose enough to explain the issue to the user,
- high-risk applications' confidential information, such as keying material and authentication information, is always wiped during the execution of `defer` blocks,
- `try!` is used only with proper guarding up front (to programmatically verify that the method that's called with `try!` can't throw an error).

#### Proper Error Handling

Developers can implement proper error handling in several ways:

- Make sure that the application uses a well-designed and unified scheme to handle errors.
- Make sure that all logging is removed or guarded as described in the test case "Testing for Debugging Code and Verbose Error Logging".
- For a high-risk application written in Objective-C: create an exception handler that removes secrets that shouldn't be easily retrievable. The handler can be set via `NSSetUncaughtExceptionHandler`.
- Refrain from using `try!` in Swift unless you're certain that there's no error in the throwing method that's being called.
- Make sure that the Swift error doesn't propagate into too many intermediate methods.

### Dynamic Testing

There are several dynamic analysis methods:

- Enter unexpected values in the iOS application's UI fields.
- Test the custom URL schemes, pasteboard, and other inter-app communication controls by providing unexpected or exception-raising values.
- Tamper with the network communication and/or the files stored by the application.
- For Objective-C, you can use Cycript to hook into methods and provide them arguments that may cause the callee to throw an exception.

In most cases, the application should not crash. Instead, it should

- recover from the error or enter a state from which it can inform the user that it can't continue,
- provide a message (which shouldn't leak sensitive information) to get the user to take appropriate action,
- withhold information from the application's logging mechanisms.

## Memory Corruption Bugs (MSTG-CODE-8)

iOS applications have various ways to run into memory corruption bugs: first there are the native code issues which have been mentioned in the general Memory Corruption Bugs section. Next, there are various unsafe operations with both Objective-C and Swift to actually wrap around native code which can create issues. Last, both Swift and Objective-C implementations can result in memory leaks due to retaining objects which are no longer in use.

### Static Analysis

Are there native code parts? If so: check for the given issues in the general memory corruption section. Native code is a little harder to spot when compiled. If you have the sources then you can see that C files use .c source files and .h header files and C++ uses .cpp files and .h files. This is a little different from the .swift and the .m source files for Swift and Objective-C. These files can be part of the sources, or part of third party libraries, registered as frameworks and imported through various tools, such as Carthage, the Swift Package Manager or Cocoapods.

For any managed code (Objective-C / Swift) in the project, check the following items:

- The doubleFree issue: when `free` is called twice for a given region instead of once.
- Retaining cycles: look for cyclic dependencies by means of strong references of components to one another which keep materials in memory.
- Using instances of `UnsafePointer` can be managed wrongly, which will allow for various memory corruption issues.
- Trying to manage the reference count to an object by `Unmanaged` manually, leading to wrong counter numbers and a too late/too soon release.

[A great talk is given on this subject at Realm academy](https://academy.realm.io/posts/russ-bishop-unsafe-swift/ "Russh Bishop on Unsafe Swift") and [a nice tutorial to see what is actually happening](https://www.raywenderlich.com/780-unsafe-swift-using-pointers-and-interacting-with-c "Unsafe Swift: Using Pointers And Interacting With C") is provided by Ray Wenderlich on this subject.

> Please note that with Swift 5 you can only deallocate full blocks, which means the playground has changed a bit.

### Dynamic Analysis

There are various tools provided which help to identify memory bugs within Xcode, such as the Debug Memory graph introduced in Xcode 8 and the Allocations and Leaks instrument in Xcode.

Next, you can check whether memory is freed too fast or too slow by enabling `NSAutoreleaseFreedObjectCheckEnabled`, `NSZombieEnabled`, `NSDebugEnabled` in Xcode while testing the application.

There are various well written explanations which can help with taking care of memory management. These can be found in the reference list of this chapter.

## Make Sure That Free Security Features Are Activated (MSTG-CODE-9)

### Overview

Although Xcode enables all binary security features by default, it may be relevant to verify this for an old application or to check for the misconfiguration of compilation options. The following features are applicable:

- **ARC** - Automatic Reference Counting - A memory management feature that adds retain and release messages when required
- **Stack Canary** - Helps prevent buffer overflow attacks by means of having a small integer right before the return pointer. A buffer overflow attack often overwrites a region of memory in order to overwrite the return pointer and take over the process-control. In that case, the canary gets overwritten as well. Therefore, the value of the canary is always checked to make sure it has not changed before a routine uses the return pointer on the stack.
- **PIE** - Position Independent Executable - enables full ASLR for binary

### Static Analysis

#### Xcode Project Settings

- Stack-smashing protection

Steps for enabling Stack-smashing protection in an iOS application:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that the "-fstack-protector-all" option is selected in the "Other C Flags" section.
3. Make sure that Position Independent Executables (PIE) support is enabled.

Steps for building an iOS application as PIE:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Set the iOS Deployment Target to iOS 4.3 or later.
3. Make sure that "Generate Position-Dependent Code" is set to its default value ("NO").
4. Make sure that "Don't Create Position Independent Executables" is set to its default value ("NO").

- ARC protection

Steps for enabling ACR protection for an iOS application:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that "Objective-C Automatic Reference Counting" is set to its default value ("YES").

See the [Technical Q&A QA1788 Building a Position Independent Executable](https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable").

#### With otool

Below are procedures for checking the binary security features described above. All the features are enabled in these examples.

- PIE:

    ```bash
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

- stack canary:

    ```bash
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

- Automatic Reference Counting:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep release
    0x0045b7dc 83156 ___cxa_guard_release
    0x0045fd5c 83414 _objc_autorelease
    0x0045fd6c 83415 _objc_autoreleasePoolPop
    0x0045fd7c 83416 _objc_autoreleasePoolPush
    0x0045fd8c 83417 _objc_autoreleaseReturnValue
    0x0045ff0c 83441 _objc_release
    [SNIP]
    ```

#### With idb

IDB automates the processes of checking for stack canary and PIE support. Select the target binary in the IDB GUI and click the "Analyze Binary…" button.

<img src="Images/Chapters/0x06i/idb.png" alt="IDB Analyze Binary" width="350px" />

### Dynamic Analysis

Dynamic analysis is not applicable for finding security features offered by the toolchain.

## References

### Memory management - dynamic analysis examples

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>

### OWASP MASVS

- MSTG-CODE-1: "The app is signed and provisioned with a valid certificate, of which the private key is properly protected."
- MSTG-CODE-2: "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)."
- MSTG-CODE-3: "Debugging symbols have been removed from native binaries."
- MSTG-CODE-4: "Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages."
- MSTG-CODE-5: "All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities."
- MSTG-CODE-6: "The app catches and handles possible exceptions."
- MSTG-CODE-8: "In unmanaged code, memory is allocated, freed and used securely."
- MSTG-CODE-9: "Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated."

#### Tools

- Swift Package Manager - <https://swift.org/package-manager/>
- Carthage - <https://github.com/carthage/carthage>
- CocoaPods - <https://CocoaPods.org>
- OWASP Dependency Check - <https://jeremylong.github.io/DependencyCheck/>
- Sourceclear - <https://sourceclear.com>
- class-dump - <https://github.com/nygard/class-dump>
- RetireJS - <https://retirejs.github.io/retire.js/>
- idb - <https://github.com/dmayer/idb>
- Codesign - <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>
