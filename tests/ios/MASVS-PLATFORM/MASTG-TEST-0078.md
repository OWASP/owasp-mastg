---
masvs_v1_id:
- MSTG-PLATFORM-7
masvs_v2_id:
- MASVS-PLATFORM-2
platform: ios
title: Determining Whether Native Methods Are Exposed Through WebViews
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

### Testing UIWebView JavaScript to Native Bridges

Search for code that maps native objects to the `JSContext` associated with a WebView and analyze what functionality it exposes, for example no sensitive data should be accessible and exposed to WebViews.

In Objective-C, the `JSContext` associated with a `UIWebView` is obtained as follows:

```objectivec

[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]

```

### Testing WKWebView JavaScript to Native Bridges

Verify if a JavaScript to native bridge exists by searching for `WKScriptMessageHandler` and check all exposed methods. Then verify how the methods are called.

The following example from ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/b8d4abda4000aa509c7a5de79e5c90360d1d0849/WheresMyBrowser/WKWebViewPreferencesManager.swift#L98 "Where\'s My Browser? WKWebViewPreferencesManager.swift Line 98") demonstrates this.

First we see how the JavaScript bridge is enabled:

```swift
func enableJavaScriptBridge(_ enabled: Bool) {
    options_dict["javaScriptBridge"]?.value = enabled
    let userContentController = wkWebViewConfiguration.userContentController
    userContentController.removeScriptMessageHandler(forName: "javaScriptBridge")

    if enabled {
            let javaScriptBridgeMessageHandler = JavaScriptBridgeMessageHandler()
            userContentController.add(javaScriptBridgeMessageHandler, name: "javaScriptBridge")
    }
}
```

Adding a script message handler with name `"name"` (or `"javaScriptBridge"` in the example above) causes the JavaScript function `window.webkit.messageHandlers.myJavaScriptMessageHandler.postMessage` to be defined in all frames in all web views that use the user content controller. It can be then [used from the HTML file like this](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/d4e2d9efbde8841bf7e4a8800418dda6bb116ec6/WheresMyBrowser/web/WKWebView/scenario3.html#L33 "Where\'s My Browser? WKWebView/scenario3.html Line 33"):

```javascript
function invokeNativeOperation() {
    value1 = document.getElementById("value1").value
    value2 = document.getElementById("value2").value
    window.webkit.messageHandlers.javaScriptBridge.postMessage(["multiplyNumbers", value1, value2]);
}
```

The called function resides in [`JavaScriptBridgeMessageHandler.swift`](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/b8d4abda4000aa509c7a5de79e5c90360d1d0849/WheresMyBrowser/JavaScriptBridgeMessageHandler.swift#L29 "Where\'s My Browser? JavaScriptBridgeMessageHandler.swift Line 29"):

```swift
class JavaScriptBridgeMessageHandler: NSObject, WKScriptMessageHandler {

//...

case "multiplyNumbers":

        let arg1 = Double(messageArray[1])!
        let arg2 = Double(messageArray[2])!
        result = String(arg1 * arg2)
//...

let javaScriptCallBack = "javascriptBridgeCallBack('\(functionFromJS)','\(result)')"
message.webView?.evaluateJavaScript(javaScriptCallBack, completionHandler: nil)
```

The problem here is that the `JavaScriptBridgeMessageHandler` not only contains that function, it also exposes a sensitive function:

```swift
case "getSecret":
        result = "XSRSOGKC342"
```

## Dynamic Analysis

At this point you've surely identified all potentially interesting WebViews in the iOS app and got an overview of the potential attack surface (via static analysis, the dynamic analysis techniques that we have seen in previous sections or a combination of them). This would include HTML and JavaScript files, usage of the `JSContext` / `JSExport` for `UIWebView` and `WKScriptMessageHandler` for `WKWebView`, as well as which functions are exposed and present in a WebView.

Further dynamic analysis can help you exploit those functions and get sensitive data that they might be exposing. As we have seen in the static analysis, in the previous example it was trivial to get the secret value by performing reverse engineering (the secret value was found in plain text inside the source code) but imagine that the exposed function retrieves the secret from secure storage. In this case, only dynamic analysis and exploitation would help.

The procedure for exploiting the functions starts with producing a JavaScript payload and injecting it into the file that the app is requesting. The injection can be accomplished via various techniques, for example:

- If some of the content is loaded insecurely from the Internet over HTTP (mixed content), you can try to implement a MITM attack.
- You can always perform dynamic instrumentation and inject the JavaScript payload by using frameworks like Frida and the corresponding JavaScript evaluation functions available for the iOS WebViews ([`stringByEvaluatingJavaScriptFromString:`](https://developer.apple.com/documentation/uikit/uiwebview/1617963-stringbyevaluatingjavascriptfrom?language=objc "UIWebView stringByEvaluatingJavaScriptFromString:") for `UIWebView` and [`evaluateJavaScript:completionHandler:`](https://developer.apple.com/documentation/webkit/wkwebview/1415017-evaluatejavascript?language=objc "WKWebView evaluateJavaScript:completionHandler:") for `WKWebView`).

In order to get the secret from the previous example of the "Where's My Browser?" app, you can use one of these techniques to inject the following payload that will reveal the secret by writing it to the "result" field of the WebView:

```javascript
function javascriptBridgeCallBack(name, value) {
    document.getElementById("result").innerHTML=value;
};
window.webkit.messageHandlers.javaScriptBridge.postMessage(["getSecret"]);
```

Of course, you may also use the Exploitation Helper it provides:

<img src="Images/Chapters/0x06h/exploit_javascript_bridge.png" width="400px" />

See another example for a vulnerable iOS app and function that is exposed to a WebView in [#thiel2] page 156.
