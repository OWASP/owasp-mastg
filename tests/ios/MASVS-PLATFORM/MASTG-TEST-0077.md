---
masvs_v1_id:
- MSTG-PLATFORM-6
masvs_v2_id:
- MASVS-PLATFORM-2
platform: ios
title: Testing WebView Protocol Handlers
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

- Testing How WebViews Load Content
- Testing WebView file access
- Checking telephone number detection

### Testing How WebViews Load Content

If a WebView is loading content from the app data directory, users should not be able to change the filename or path from which the file is loaded, and they shouldn't be able to edit the loaded file.

This presents an issue especially in `UIWebView`s loading untrusted content via the deprecated methods [`loadHTMLString:baseURL:`](https://developer.apple.com/documentation/uikit/uiwebview/1617979-loadhtmlstring?language=objc "UIWebView loadHTMLString:baseURL:") or [`loadData:MIMEType:textEncodingName:baseURL:`](https://developer.apple.com/documentation/uikit/uiwebview/1617941-loaddata?language=objc "UIWebView loadData:MIMEType:textEncodingName:baseURL:") and setting the `baseURL` parameter to `nil` or to a `file:` or `applewebdata:` URL schemes. In this case, in order to prevent unauthorized access to local files, the best option is to set it instead to `about:blank`. However, the recommendation is to avoid the use of `UIWebView`s and switch to `WKWebView`s instead.

Here's an example of a vulnerable `UIWebView` from ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/UIWebViewController.swift#L219 "Where\'s My Browser? UIWebViewController.swift Line 219"):

```default
let scenario2HtmlPath = Bundle.main.url(forResource: "web/UIWebView/scenario2.html", withExtension: nil)
do {
    let scenario2Html = try String(contentsOf: scenario2HtmlPath!, encoding: .utf8)
    uiWebView.loadHTMLString(scenario2Html, baseURL: nil)
} catch {}
```

The page loads resources from the internet using HTTP, enabling a potential MITM to exfiltrate secrets contained in local files, e.g. in shared preferences.

When working with `WKWebView`s, Apple recommends using [`loadHTMLString:baseURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1415004-loadhtmlstring?language=objc "WKWebView loadHTMLString:baseURL:") or [`loadData:MIMEType:textEncodingName:baseURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1415011-loaddata?language=objc "WKWebView loadData:MIMEType:textEncodingName:baseURL:") to load local HTML files and `loadRequest:` for web content. Typically, the local files are loaded in combination with methods including, among others: [`pathForResource:ofType:`](https://developer.apple.com/documentation/foundation/nsbundle/1410989-pathforresource "NSBundle pathForResource:ofType:"), [`URLForResource:withExtension:`](https://developer.apple.com/documentation/foundation/nsbundle/1411540-urlforresource?language=objc "NSBundle URLForResource:withExtension:") or [`init(contentsOf:encoding:)`](https://developer.apple.com/documentation/swift/string/3126736-init "String init(contentsOf:encoding:)").

Search the source code for the mentioned methods and inspect their parameters.

Example in Objective-C:

```objectivec

- (void)viewDidLoad
{
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];

    self.webView = [[WKWebView alloc] initWithFrame:CGRectMake(10, 20,
        CGRectGetWidth([UIScreen mainScreen].bounds) - 20,
        CGRectGetHeight([UIScreen mainScreen].bounds) - 84) configuration:configuration];
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"example_file" ofType:@"html"];
    NSString *html = [NSString stringWithContentsOfFile:filePath
                                encoding:NSUTF8StringEncoding error:nil];
    [self.webView loadHTMLString:html baseURL:[NSBundle mainBundle].resourceURL];
}

```

Example in Swift from ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/WKWebViewController.swift#L196 "Where\'s My Browser? WKWebViewController.swift Line 196"):

```default
let scenario2HtmlPath = Bundle.main.url(forResource: "web/WKWebView/scenario2.html", withExtension: nil)
do {
    let scenario2Html = try String(contentsOf: scenario2HtmlPath!, encoding: .utf8)
    wkWebView.loadHTMLString(scenario2Html, baseURL: nil)
} catch {}
```

If only having the compiled binary, you can also search for these methods using @MASTG-TOOL-0129:

```bash
$ rabin2 -zz ./WheresMyBrowser | grep -i "loadHTMLString"
231 0x0002df6c 24 (4.__TEXT.__objc_methname) ascii loadHTMLString:baseURL:
```

In a case like this, it is recommended to perform dynamic analysis to ensure that this is in fact being used and from which kind of WebView. The `baseURL` parameter here doesn't present an issue as it will be set to "null" but could be an issue if not set properly when using a `UIWebView`. See "Checking How WebViews are Loaded" for an example about this.

In addition, you should also verify if the app is using the method [`loadFileURL: allowingReadAccessToURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1414973-loadfileurl?language=objc "WKWebView loadFileURL:allowingReadAccessToURL:"). Its first parameter is `URL` and contains the URL to be loaded in the WebView, its second parameter `allowingReadAccessToURL` may contain a single file or a directory. If containing a single file, that file will be available to the WebView. However, if it contains a directory, all files on that directory will be made available to the WebView. Therefore, it is worth inspecting this and in case it is a directory, verifying that no sensitive data can be found inside it.

Example in Swift from ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/WKWebViewController.swift#L186 "Where\'s My Browser? WKWebViewController.swift Line 186"):

```default
var scenario1Url = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
scenario1Url = scenario1Url.appendingPathComponent("WKWebView/scenario1.html")
wkWebView.loadFileURL(scenario1Url, allowingReadAccessTo: scenario1Url)
```

In this case, the parameter `allowingReadAccessToURL` contains a single file "WKWebView/scenario1.html", meaning that the WebView has exclusively access to that file.

In the compiled binary you can use @MASTG-TOOL-0129:

```bash
$ rabin2 -zz ./WheresMyBrowser | grep -i "loadFileURL"
237 0x0002dff1 37 (4.__TEXT.__objc_methname) ascii loadFileURL:allowingReadAccessToURL:
```

### Testing WebView File Access

If you have found a `UIWebView` being used, then the following applies:

- The `file://` scheme is always enabled.
- File access from `file://` URLs is always enabled.
- Universal access from `file://` URLs is always enabled.

Regarding `WKWebView`s:

- The `file://` scheme is also always enabled and it **cannot be disabled**.
- It disables file access from `file://` URLs by default but it can be enabled.

The following WebView properties can be used to configure file access:

- `allowFileAccessFromFileURLs` (`WKPreferences`, `false` by default): it enables JavaScript running in the context of a `file://` scheme URL to access content from other `file://` scheme URLs.
- `allowUniversalAccessFromFileURLs` (`WKWebViewConfiguration`, `false` by default): it enables JavaScript running in the context of a `file://` scheme URL to access content from any origin.

For example, it is possible to set the **[undocumented property](https://github.com/WebKit/webkit/blob/master/Source/WebKit/UIProcess/API/Cocoa/WKPreferences.mm#L470 "WebKit WKPreferences.mm Line 470")** `allowFileAccessFromFileURLs` by doing this:

Objective-C:

```objectivec

[webView.configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];

```

Swift:

```default

webView.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")

```

If one or more of the above properties are activated, you should determine whether they are really necessary for the app to work properly.

### Checking Telephone Number Detection

In Safari on iOS, telephone number detection is on by default. However, you might want to turn it off if your HTML page contains numbers that can be interpreted as phone numbers, but are not phone numbers, or to prevent the DOM document from being modified when parsed by the browser. To turn off telephone number detection in Safari on iOS, use the format-detection meta tag (`<meta name = "format-detection" content = "telephone=no">`). An example of this can be found in the [Apple developer documentation](https://developer.apple.com/library/archive/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html#//apple_ref/doc/uid/TP40007899-CH6-SW2 "Phone Links: Turning telephone number detection off"). Phone links should be then used (e.g. `<a href="tel:1-408-555-5555">1-408-555-5555</a>`) to explicitly create a link.

## Dynamic Analysis

If it's possible to load local files via a WebView, the app might be vulnerable to directory traversal attacks. This would allow access to all files within the sandbox or even to escape the sandbox with full access to the file system (if the device is jailbroken). It should therefore be verified if a user can change the filename or path from which the file is loaded, and they shouldn't be able to edit the loaded file.

To simulate an attack, you may inject your own JavaScript into the WebView with an interception proxy or simply by using dynamic instrumentation. Attempt to access local storage and any native methods and properties that might be exposed to the JavaScript context.

In a real-world scenario, JavaScript can only be injected through a permanent backend Cross-Site Scripting vulnerability or a MITM attack. See the OWASP [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html "XSS (Cross-Site Scripting) Prevention Cheat Sheet") and the chapter "[iOS Network Communication](../../../Document/0x06g-Testing-Network-Communication.md)" for more information.

For what concerns this section we will learn about:

- Testing How WebViews Load Content
- Determining WebView file access

### Testing How WebViews Load Content

If `WKWebView`'s "scenario 2" of the ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/WKWebViewController.swift#L196) app is loaded, the app will do so by calling [`URLForResource:withExtension:`](https://developer.apple.com/documentation/foundation/nsbundle/1411540-urlforresource?language=objc "NSBundle URLForResource:withExtension:") and `loadHTMLString:baseURL`.

To quickly inspect this, you can use frida-trace and trace all `loadHTMLString` and `URLForResource:withExtension:` methods.

```bash
$ frida-trace -U "Where's My Browser?"
    -m "*[WKWebView *loadHTMLString*]" -m "*[* URLForResource:withExtension:]"

 14131 ms  -[NSBundle URLForResource:0x1c0255390 withExtension:0x0]
 14131 ms  URLForResource: web/WKWebView/scenario2.html
 14131 ms  withExtension: 0x0
 14190 ms  -[WKWebView loadHTMLString:0x1c0255390 baseURL:0x0]
 14190 ms   HTMLString: <!DOCTYPE html>
    <html>
        ...
        </html>

 14190 ms  baseURL: nil
```

In this case, `baseURL` is set to `nil`, meaning that the effective origin is "null". You can obtain the effective origin by running `window.origin` from the JavaScript of the page (this app has an exploitation helper that allows to write and run JavaScript, but you could also implement a MITM or simply use Frida to inject JavaScript, e.g. via `evaluateJavaScript:completionHandler` of `WKWebView`).

As an additional note regarding `UIWebView`s, if you retrieve the effective origin from a `UIWebView` where `baseURL` is also set to `nil` you will see that it is not set to "null", instead you'll obtain something similar to the following:

```bash
applewebdata://5361016c-f4a0-4305-816b-65411fc1d780
```

This origin "applewebdata://" is similar to the "file://" origin as it does not implement Same-Origin Policy and allow access to local files and any web resources. In this case, it would be better to set `baseURL` to "about:blank", this way, the Same-Origin Policy would prevent cross-origin access. However, the recommendation here is to completely avoid using `UIWebView`s and go for `WKWebView`s instead.

### Determining WebView File Access

Even if not having the original source code, you can quickly determine if the app's WebViews do allow file access and which kind. For this, simply navigate to the target WebView in the app and inspect all its instances, for each of them get the values mentioned in the static analysis, that is, `allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs`. This only applies to `WKWebView`s (`UIWebVIew`s always allow file access).

We continue with our example using the ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/ "Where\'s My Browser?") app and Frida REPL, extend the script with the following content:

```javascript
ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('URL: ', wk.URL().toString());
    console.log('javaScriptEnabled: ', wk.configuration().preferences().javaScriptEnabled());
    console.log('allowFileAccessFromFileURLs: ',
            wk.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
    console.log('hasOnlySecureContent: ', wk.hasOnlySecureContent().toString());
    console.log('allowUniversalAccessFromFileURLs: ',
            wk.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
  },
  onComplete: function () {
    console.log('done for WKWebView!');
  }
});
```

If you run it now, you'll have all the information you need:

```javascript
$ frida -U -f com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>
URL:  file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
        Library/WKWebView/scenario1.html
javaScriptEnabled:  true
allowFileAccessFromFileURLs:  0
hasOnlySecureContent:  false
allowUniversalAccessFromFileURLs:  0
```

Both `allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs` are set to "0", meaning that they are disabled. In this app we can go to the WebView configuration and enable `allowFileAccessFromFileURLs`. If we do so and re-run the script we will see how it is set to "1" this time:

```bash
$ frida -U -f com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js
...

allowFileAccessFromFileURLs:  1
```
