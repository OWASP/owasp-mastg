# iOS Code Quality and Build Settings

## Overview

### App Signing

[Code signing](0x06a-Platform-Overview.md#code-signing) your app assures users that the app has a known source and hasn't been modified since it was last signed. Before your app can integrate app services, be installed on a non-jailbroken device, or be submitted to the App Store, it must be signed with a certificate issued by Apple. For more information on how to request certificates and code sign your apps, review the [App Distribution Guide](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html "App Distribution Guide").

### Third-Party Libraries

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

### Memory Corruption Bugs

iOS applications have various ways to run into [memory corruption bugs](0x04h-Testing-Code-Quality.md#memory-corruption-bugs): first there are the native code issues which have been mentioned in the general Memory Corruption Bugs section. Next, there are various unsafe operations with both Objective-C and Swift to actually wrap around native code which can create issues. Last, both Swift and Objective-C implementations can result in memory leaks due to retaining objects which are no longer in use.

Learn more:

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>

### Binary Protection Mechanisms

Detecting the presence of [binary protection mechanisms](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) heavily depend on the language used for developing the application.

Although Xcode enables all binary security features by default, it may be relevant to verify this for old applications or to check for compiler flag misconfigurations. The following features are applicable:

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
  - PIE applies to executable binaries (Mach-O type `MH_EXECUTE`).
  - However it's not applicable for libraries (Mach-O type `MH_DYLIB`).
- [**Memory management**](0x04h-Testing-Code-Quality.md#memory-management):
  - Both pure Objective-C, Swift and hybrid binaries should have ARC (Automatic Reference Counting) enabled.
  - For C/C++ libraries, the developer is responsible for doing proper [manual memory management](0x04h-Testing-Code-Quality.md#manual-memory-management). See ["Memory Corruption Bugs (MSTG-CODE-8)"](#memory-corruption-bugs-mstg-code-8).
- [**Stack Smashing Protection**](0x04h-Testing-Code-Quality.md#stack-smashing-protection): For pure Objective-C binaries, this should always be enabled. Since Swift is designed to be memory safe, if a library is purely written in Swift, and stack canaries weren’t enabled, the risk will be minimal.

Learn more:

- [OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [On iOS Binary Protections](https://sensepost.com/blog/2021/on-ios-binary-protections/)
- [Security of runtime process in iOS and iPadOS](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- [Mach-O Programming Topics - Position-Independent Code](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/dynamic_code.html)

Tests to detect the presence of these protection mechanisms heavily depend on the language used for developing the application. For example, existing techniques for detecting the presence of stack canaries do not work for pure Swift apps.

#### Xcode Project Settings

##### Stack Canary protection

Steps for enabling stack canary protection in an iOS application:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that the "-fstack-protector-all" option is selected in the "Other C Flags" section.
3. Make sure that Position Independent Executables (PIE) support is enabled.

##### PIE protection

Steps for building an iOS application as PIE:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Set the iOS Deployment Target to iOS 4.3 or later.
3. Make sure that "Generate Position-Dependent Code" (section "Apple Clang - Code Generation") is set to its default value ("NO").
4. Make sure that "Generate Position-Dependent Executable" (section "Linking") is set to its default value ("NO").

##### ARC protection

ARC is automatically enabled for Swift apps by the `swiftc` compiler. However, for Objective-C apps you'll have ensure that it's enabled by following these steps:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that "Objective-C Automatic Reference Counting" is set to its default value ("YES").

See the [Technical Q&A QA1788 Building a Position Independent Executable](https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable").

### Debuggable Apps

Apps can be made [debuggable](0x06c-Reverse-Engineering-and-Tampering.md#debugging) by adding the [`get-task-allow`](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues "Resolving common notarization issues") key to the app entitlements file and setting it to `true`.

While debugging is a useful feature when developing an app, it has to be turned off before releasing apps to the App Store or within an enterprise program. To do that you need to determine the mode in which your app is to be generated to check the flags in the environment:

- Select the build settings of the project
- Under 'Apple LVM - Preprocessing' and 'Preprocessor Macros', make sure 'DEBUG' or 'DEBUG_MODE' is not selected (Objective-C)
- Make sure that the "Debug executable" option is not selected.
- Or in the 'Swift Compiler - Custom Flags' section / 'Other Swift Flags', make sure the '-D DEBUG' entry does not exist.

### Debugging Symbols

As a good practice, as little explanatory information as possible should be provided with a compiled binary. The presence of additional metadata such as debug symbols might provide valuable information about the code, e.g. function names leaking information about what a function does. This metadata is not required to execute the binary and thus it is safe to discard it for the release build, which can be done by using proper compiler configurations. As a tester you should inspect all binaries delivered with the app and ensure that no debugging symbols are present (at least those revealing any valuable information about the code).

When an iOS application is compiled, the compiler generates a list of debug symbols for each binary file in an app (the main app executable, frameworks, and app extensions). These symbols include class names, global variables, and method and function names which are mapped to specific files and line numbers where they're defined. [Debug builds](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building Your App to Include Debugging Information") of an app place the debug symbols in a compiled binary by default, while release builds of an app place them in a companion _Debug Symbol file_ (dSYM) to reduce the size of the distributed app.

### Debugging Code and Error Logging

To speed up verification and get a better understanding of errors, developers often include debugging code, such as verbose logging statements (using `NSLog`, `println`, `print`, `dump`, and `debugPrint`) about responses from their APIs and about their application's progress and/or state. Furthermore, there may be debugging code for "management-functionality", which is used by developers to set the application's state or mock responses from an API. Reverse engineers can easily use this information to track what's happening with the application. Therefore, debugging code should be removed from the application's release version.

### Exception Handling

Exceptions often occur after an application enters an abnormal or erroneous state.
Testing exception handling is about making sure that the application will handle the exception and get into a safe state without exposing any sensitive information via its logging mechanisms or the UI.

Bear in mind that exception handling in Objective-C is quite different from exception handling in Swift. Bridging the two approaches in an application that is written in both legacy Objective-C code and Swift code can be problematic.

#### Exception Handling in Objective-C

Objective-C has two types of errors:

**NSException:**

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

**NSError:**

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
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/book.json") else {
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
