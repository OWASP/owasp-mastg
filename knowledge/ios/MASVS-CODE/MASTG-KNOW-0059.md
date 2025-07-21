---
masvs_category: MASVS-CODE
platform: ios
title: Third-Party Libraries
---

iOS applications often make use of third party libraries which accelerate development as the developer has to write less code in order to solve a problem. However, third party libraries may contain vulnerabilities, incompatible licensing, or malicious content. Additionally, it is difficult for organizations and developers to manage application dependencies, including monitoring library releases and applying available security patches.

There are three widely used package management tools [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org"), [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub"), and [CocoaPods](https://cocoapods.org "CocoaPods.org"):

- The Swift Package Manager is open source, included with the Swift language, integrated into Xcode (since Xcode 11) and supports [Swift, Objective-C, Objective-C++, C, and C++](https://developer.apple.com/documentation/xcode/swift-packages "Swift Packages Documentation") packages. It is written in Swift, decentralized and uses the Package.swift file to document and manage project dependencies.
- Carthage is open source and can be used for Swift and Objective-C packages. It is written in Swift, decentralized and uses the Cartfile file to document and manage project dependencies.
- CocoaPods is open source and can be used for Swift and Objective-C packages. It is written in Ruby, utilizes a centralized package registry for public and private packages and uses the Podfile file to document and manage project dependencies.

There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `OHHTTPStubs` used for testing.
- Libraries that are packed within the actual production application, such as `Alamofire`.

These libraries can lead to unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example is `AFNetworking` version 2.5.1, which contained a bug that disabled certificate validation. This vulnerability would allow attackers to execute [Machine-in-the-Middle (MITM)](0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attacks against apps that are using the library to connect to their APIs.
- A library can no longer be maintained or hardly be used, which is why no vulnerabilities are reported and/or fixed. This can lead to having bad and/or vulnerable code in your application through the library.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its source code. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.
