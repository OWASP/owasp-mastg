## iOS Platform APIs

### Testing Custom URL Schemes

#### Overview

In contrast to Android's rich Inter-Process Communication (IPC) capability, iOS offers few options for communication between apps. In fact, there's no way for apps to communicate directly. Instead, Apple offers [two types of indirect communication](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html): file transfer through AirDrop and custom URL schemes.

Custom URL schemes allow apps to communicate via a custom protocol. An app must declare support for the scheme and handle incoming URLs that use the scheme. Once the URL scheme is registered, other apps can open the app that registered the scheme, and pass parameters by creating appropriately formatted URLs and opening them with the `openURL` method.

Security issues arise when an app processes calls to its URL scheme without properly validating the URL and its parameters and when users aren't prompted for confirmation before triggering an important action.

One example is the following [bug in the Skype Mobile app](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html), discovered in 2010: The Skype app registered the `skype://` protocol handler, which allowed other apps to trigger calls to other Skype users and phone numbers. Unfortunately, Skype didn't ask users for permission before placing the calls, so any app could call arbitrary numbers without the user's knowledge.

Attackers exploited this vulnerability by putting an invisible `<iframe src="skype://xxx?call"></iframe>` (where `xxx` was replaced by a premium number), so any Skype user who inadvertently visited a malicious website called the premium number.

#### Static Analysis

The first step to test custom URL schemes is finding out whether an application registers any protocol handlers. This information is in the file `info.plist` in the application sandbox folder. To view registered protocol handlers, simply open a project in Xcode, go to the `Info` tab, and open the `URL Types` section, presented in the screenshot below.

![Document Overview](Images/Chapters/0x06h/URL_scheme.png)

Next, determine how a URL path is built and validated. The method [`openURL`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc) is responsible for handling user URLs. Look for implemented controls: how URLs are validated (the input it accepts) and whether it needs user permission when using the custom URL schema?

In a compiled application, registered protocol handlers are found in the file `Info.plist`. To find a URL structure, look for uses of the `CFBundleURLSchemes` key using `strings` or `Hopper`:

```sh
$ strings <yourapp> | grep "myURLscheme://"
```

You should carefully validate any URL before calling it. You can whitelist applications which may be opened via the registered protocol handler. Prompting users to confirm the URL-invoked action is another helpful control.

#### Dynamic Analysis

Once you've identified the custom URL schemes the app has registered, open the URLs on Safari and observe how the app behaves.

If the app parses parts of the URL, you can perform input fuzzing to detect memory corruption bugs. For this you can use [IDB](http://www.idbtool.com/):

- Start IDB, connect to your device and select the target app. You can find details in the [IDB documentation](http://www.idbtool.com/documentation/setup.html).
- Go to the `URL Handlers` section. In `URL schemes`, click `Refresh` , and on the left you'll find a list of all custom schemes defined in the app being tested. You can load these schemes by clicking `Open`, on the right side. By simply opening a blank URI scheme (e.g., opening `myURLscheme://`), you can discover hidden functionality (e.g., a debug window) and bypass local authentication.
- To find out whether custom URI schemes contain any bugs, try to fuzz them. In the `URL Handlers` section, go to the `Fuzzer` tab. On the left side default IDB payloads are listed. The [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) project offers fuzzing dictionaries. Once your payload list is ready, go to the `Fuzz Template` section in the left bottom panel and define a template. Use `$@$` to define an injection point, for example:

```sh
myURLscheme://$@$
```

While the URL scheme is being fuzzed, watch the logs (in Xcode, go to `Window -> Devices ->` *click on your device* `->` *bottom console contains logs*) to observe the impact of each payload. The history of used payloads is on the right side of the IDB `Fuzzer` tab .

Needle can be used to test custom URL schemes, manual fuzzing can be performed against the URL scheme to identify input validation and memory corruption bugs. The following Needle module should be used to perform these attacks:

```
[needle] > 
[needle] > use dynamic/ipc/open_uri
[needle][open_uri] > show options

  Name  Current Value  Required  Description
  ----  -------------  --------  -----------
  URI                  yes       URI to launch, eg tel://123456789 or http://www.google.com/

[needle][open_uri] > set URI "myapp://testpayload'"
URI => "myapp://testpayload'"
[needle][open_uri] > run

```

### Testing iOS WebViews

#### Overview

WebViews are in-app browser components for displaying interactive web content. They can be used to embed web content directly into an app's user interface.

iOS WebViews support JavaScript execution by default, so script injection and cross-site scripting attacks can affect them. Starting from iOS version 7.0, Apple also introduced APIs that allow communication between the JavaScript runtime in the WebView and the native Swift or Objective-C app. If these APIs are used carelessly, important functionality might be exposed to attackers who manage to inject malicious script into the WebView (e.g., through a successful cross-site scripting attack).

Besides potential script injection, there's another fundamental WebViews security issue: the WebKit libraries packaged with iOS don't get updated out-of-band like the Safari web browser. Therefore, newly discovered WebKit vulnerabilities remain exploitable until the next full iOS update [#THIEL].

WebViews support different URL schemas, like for example tel. Detection of the [tel:// schema can be disabled](https://developer.apple.com/library/content/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html "Phone Links on iOS") in the HTML page and will then not be interpreted by the WebView.

#### Static Analysis

Look out for usages of the following components that implement WebViews:

- [UIWebView](https://developer.apple.com/reference/uikit/uiwebview "UIWebView reference documentation") (for iOS versions 7.1.2 and older)
- [WKWebView](https://developer.apple.com/reference/webkit/wkwebview "WKWebView reference documentation") (for iOS in version 8.0 and later)
- [SFSafariViewController](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)

`UIWebView` is deprecated and should not be used. Make sure that either `WKWebView` or `SafariViewController` are used to embed web content:

- `WKWebView` is the appropriate choice for extending app functionality, controlling displayed content  (i.e., prevent the user from navigating to arbitrary URLs) and customizing.
- `SafariViewController` should be used to provide a generalized web viewing experience. Note that `SafariViewController` shares cookies and other website data with Safari.

`WKWebView` comes with several security advantages over `UIWebView`:

- The `JavaScriptEnabled` property can be used to completely disable JavaScript in the WKWebView. This prevents all script injection flaws.
- The `JavaScriptCanOpenWindowsAutomatically` can be used to prevent JavaScript from opening new windows, such as pop-ups.
- the `hasOnlySecureContent` property can be used to verify resources loaded by the WebView are retrieved through encrypted connections.
- WKWebView implements out-of-process rendering, so memory corruption bugs won't affect the main app process.

##### JavaScript Configuration

As a best practice, disable JavaScript in a `WKWebView` unless it is explicitly required. The following code sample shows a sample configuration.

```objective-c
#import "ViewController.h"
#import <WebKit/WebKit.h>
@interface ViewController ()<WKNavigationDelegate,WKUIDelegate>
@property(strong,nonatomic) WKWebView *webView;
@end

@implementation ViewController

- (void)viewDidLoad {

    NSURL *url = [NSURL URLWithString:@"http://www.example.com/"];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    WKPreferences *pref = [[WKPreferences alloc] init];

    //Disable javascript execution:
    [pref setJavaScriptEnabled:NO];
    [pref setJavaScriptCanOpenWindowsAutomatically:NO];

    WKWebViewConfiguration *conf = [[WKWebViewConfiguration alloc] init];
    [conf setPreferences:pref];
    _webView = [[WKWebView alloc]initWithFrame:CGRectMake(self.view.frame.origin.x,85, self.view.frame.size.width, self.view.frame.size.height-85) configuration:conf] ;
    [_webView loadRequest:request];
    [self.view addSubview:_webView];

}
```

JavaScript cannot be disabled in `SafariViewController` and this is one of the reason why you should recommend usage of `WKWebView` when the goal is extending the app's user interface.

##### Exposure of Native Objects

Both `UIWebView` and `WKWebView` provide a means of communication between the WebView and the native app. Any important data or native functionality exposed to the WebView JavaScript engine would also be accessible to rogue JavaScript running in the WebView.

###### UIWebView

Since iOS 7, the JavaScriptCore framework provides an Objective-C wrapper to the WebKit JavaScript engine. This makes it possible to execute JavaScript from Swift and Objective-C, as well as making Objective-C and Swift objects accessible from the JavaScript runtime.

A JavaScript execution environment is represented by a `JSContext` object. Look out for code that maps native objects to the `JSContext` associated with a WebView. In Objective-C, the `JSContext` associated with a `UIWebView` is obtained as follows:

``objective-c
[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]
``

- Objective-C blocks. When an Objective-C block is assigned to an identifier in a JSContext, JavaScriptCore automatically wraps the block in a JavaScript function;
- JSExport protocol: Properties, instance methods, and class methods declared in a JSExport-inherited protocol are mapped to JavaScript objects that are available to all JavaScript code. Modifications of objects that are in the JavaScript environment are reflected in the native environment.

Note that only class members defined in the `JSExport` protocol are made accessible to JavaScript code.

###### WKWebView

In contrast to `UIWebView`, it is not possible to directly reference the `JSContext` of a `WKWebView`. Instead, communication is implemented using a messaging system. JavaScript code can send messages back to the native app using the 'postMessage' method:

```javascript
window.webkit.messageHandlers.myHandler.postMessage()
````

The `postMessage` API automatically serializes JavaScript objects into native Objective-C or Swift objects. Message Handler are configured using the `addScriptMessageHandler` method.


##### Local File Inclusion

WebViews can load content remotely and locally from the app data directory. If the content is loaded locally, users should not be able to change the filename or path from which the file is loaded, and they shouldn't be able to edit the loaded file.

Check the source code for WebViews usage. If you can identify a WebView instance, check whether any local files have been loaded ("example_file.html" in the below example).

```objective-c
- (void)viewDidLoad
{
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];

    self.webView = [[WKWebView alloc] initWithFrame:CGRectMake(10, 20, CGRectGetWidth([UIScreen mainScreen].bounds) - 20, CGRectGetHeight([UIScreen mainScreen].bounds) - 84) configuration:configuration];
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"example_file" ofType:@"html"];
    NSString *html = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    [self.webView loadHTMLString:html baseURL:[NSBundle mainBundle].resourceURL];
}
```

Check the `baseURL` for dynamic parameters that can be manipulated (leading to local file inclusion).

#### Dynamic Analysis

To simulate an attack, inject your own JavaScript into the WebView with an interception proxy. Attempt to access local storage and any native methods and properties that might be exposed to the JavaScript context.

In a real-world scenario, JavaScript can only be injected through a permanent backend Cross-Site Scripting vulnerability or a man-in-the-middle attack. See the OWASP [XSS cheat sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting\)\_Prevention_Cheat_Sheet "XSS (Cross Site Scripting) Prevention Cheat Sheet") and the chapter "Testing Network Communication" for more information.

### References

#### OWASP Mobile Top 10 2016

- M7 - Client-Side Injection - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.3: "The app does not export sensitive functionality via custom URL schemes unless they are properly protected."
- V6.5: "JavaScript is disabled in WebViews unless explicitly required."
- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."
- V6.7: "If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package."

#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-939: Improper Authorization in Handler for Custom URL Scheme

#### Info

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition.

#### Tools
- IDB - http://www.idbtool.com/
