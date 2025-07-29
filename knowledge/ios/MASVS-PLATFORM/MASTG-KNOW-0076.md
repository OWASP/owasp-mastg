---
masvs_category: MASVS-PLATFORM
platform: ios
title: WebViews
---

WebViews are in-app browser components for displaying interactive web content. They can be used to embed web content directly into an app's user interface. iOS WebViews support JavaScript execution by default, so script injection and Cross-Site Scripting attacks can affect them.

## Types of WebViews

There are multiple ways to include a WebView in an iOS application:

- `UIWebView`
- `WKWebView`
- `SFSafariViewController`

## UIWebView

[`UIWebView`](https://developer.apple.com/reference/uikit/uiwebview "UIWebView") is deprecated starting on iOS 12 and [should not be used](https://medium.com/ios-os-x-development/security-flaw-with-uiwebview-95bbd8508e3c "Security Flaw with UIWebView"). Make sure that either `WKWebView` or `SFSafariViewController` are used to embed web content. In addition to that, JavaScript cannot be disabled for `UIWebView` which is another reason to refrain from using it.

## WKWebView

[`WKWebView`](https://developer.apple.com/reference/webkit/wkwebview "WKWebView") was introduced with iOS 8 and is the appropriate choice for extending app functionality, controlling displayed content (i.e., prevent the user from navigating to arbitrary URLs) and customizing.

`WKWebView` comes with several security advantages over `UIWebView`:

- JavaScript is enabled by default but thanks to the `javaScriptEnabled` property of `WKWebView`, it can be completely disabled, preventing all script injection flaws.
- The `JavaScriptCanOpenWindowsAutomatically` can be used to prevent JavaScript from opening new windows, such as pop-ups.
- The `hasOnlySecureContent` property can be used to verify resources loaded by the WebView are retrieved through encrypted connections.
- `WKWebView` implements out-of-process rendering, so memory corruption bugs won't affect the main app process.

A JavaScript Bridge can be enabled when using `WKWebView` and `UIWebView`. See Section ["Native Functionality Exposed Through WebViews"](#native-functionality-exposed-through-webviews "Native Functionality Exposed Through WebViews") below for more information.

## SFSafariViewController

[`SFSafariViewController`](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller "SFSafariViewController") is available starting on iOS 9 and should be used to provide a generalized web viewing experience. These WebViews can be easily spotted as they have a characteristic layout which includes the following elements:

- A read-only address field with a security indicator.
- An Action ("Share") button.
- A Done button, back and forward navigation buttons, and a "Safari" button to open the page directly in Safari.

<img src="Images/Chapters/0x06h/sfsafariviewcontroller.png" width="400px" />

There are a couple of things to consider:

- JavaScript cannot be disabled in `SFSafariViewController` and this is one of the reasons why the usage of `WKWebView` is recommended when the goal is extending the app's user interface.
- `SFSafariViewController` also shares cookies and other website data with Safari.
- The user's activity and interaction with a `SFSafariViewController` are not visible to the app, which cannot access AutoFill data, browsing history, or website data.
- According to the App Store Review Guidelines, `SFSafariViewController`s may not be hidden or obscured by other views or layers.

This should be sufficient for an app analysis and therefore, `SFSafariViewController`s are out of scope for the Static and Dynamic Analysis sections.

## Safari Web Inspector

Enabling the [Safari Web Inspector](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/Safari_Developer_Guide/GettingStarted/GettingStarted.html) on iOS allows you to remotely [inspect the contents of a WebView from a macOS device](https://developer.apple.com/documentation/safari-developer-tools/inspecting-ios). This is particularly useful in applications that expose native APIs using a JavaScript bridge, such as hybrid applications.

The Safari Web Inspector requires apps to have the `get-task-allowed` entitlement. The Safari app has this entitlement by default, so you can view the contents of any page loaded into it. However, applications installed from the App Store will not have this entitlement and cannot be attached. On jailbroken devices, you can add this entitlement to any application by installing @MASTG-TOOL-0137. Then, you can attach Safari on your host to examine the contents of the WebView (see @MASTG-TECH-0139).

## Native Functionality Exposed Through WebViews

In iOS 7, Apple introduced APIs that allow communication between the JavaScript runtime in the WebView and the native Swift or Objective-C objects. If these APIs are used carelessly, important functionality might be exposed to attackers who manage to inject malicious scripts into the WebView (e.g., through a successful Cross-Site Scripting attack).

Both `UIWebView` and `WKWebView` provide a means of communication between the WebView and the native app. Any important data or native functionality exposed to the WebView JavaScript engine would also be accessible to rogue JavaScript running in the WebView.

**UIWebView:**

There are two fundamental ways of how native code and JavaScript can communicate:

- **JSContext**: When an Objective-C or Swift block is assigned to an identifier in a `JSContext`, JavaScriptCore automatically wraps the block in a JavaScript function.
- **JSExport protocol**: Properties, instance methods and class methods declared in a `JSExport`-inherited protocol are mapped to JavaScript objects that are available to all JavaScript code. Modifications of objects that are in the JavaScript environment are reflected in the native environment.

Note that only class members defined in the `JSExport` protocol are made accessible to JavaScript code.

**WKWebView:**

JavaScript code in a `WKWebView` can still send messages back to the native app but in contrast to `UIWebView`, it is not possible to directly reference the `JSContext` of a `WKWebView`. Instead, communication is implemented using a messaging system and using the `postMessage` function, which automatically serializes JavaScript objects into native Objective-C or Swift objects. Message handlers are configured using the method [`add(_ scriptMessageHandler:name:)`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller/1537172-add "WKUserContentController add(_ scriptMessageHandler:name:)").
