## Testing Platform Interaction on iOS

### Testing Custom URL Schemes

#### Overview

In contrast to Android's rich Inter-Process Communication (IPC) facilities, iOS is offering only very few options for apps to talk to each other. In fact, there is no way for apps to communicate directly. Instead, Apple offers [two ways of indirect communication](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html): Sending Files between apps through AirDrop, and custom URL schemes.

Custom URL schemes allow an app to communicate with other apps through a custom protocol. For this to work, an app must declare support for the scheme and handle incoming URLs that use the scheme. Once the URL scheme is registered, other apps can open the app and pass parameters by creating an appropriately formatted URL and opening it using the `openURL` method.

Security issues arise when an app processes calls to its URL scheme without properly validating the URL and its parameters, or if the user is not prompted for confirmation before triggering a critical action.

A nice example it the following [bug in the Skype Mobile app](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html) discovered in 2010. The Skype app registered the `skype://` protocol handler, which allowed other apps to trigger calls to other Skype users and phone numbers. Unfortunately, Skype didn't ask the user for permission before placing the call, so it was possible for any app to call arbitrary numbers (without the user's knowledge if they weren't looking at their phone).

Attackers exploited this vulnerability by putting an invisible `<iframe src=”skype://xxx?call"></iframe>` (where `xxx` was replaced by a premium number), so any Skype user who visited a malicious website inadvertently called the premium number.

#### Static Analysis

The first step is to find out if an application registers any protocol handlers. This information can be found in `info.plist` file in the application sandbox folder. To view registered protocol handlers, simply open a project in Xcode, go to `Info` tab and open `URL Types` section, as it is presented on a below screenshot.

![Document Overview](Images/Chapters/0x06h/URL_scheme.png)

Then, you should verify how an URL path is built and validated. A method responsible for handling user's URLs is called [`openURL`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc). Look for implemented controls - how an URL is validated (what input it accepts) and does it need the permission of the user when using the custom URL schema?

In a compiled application, you can find registered protocol handlers in a `Info.plist` file under the `CFBundleURLTypes` and then under `CFBundleURLSchemes` key. To find out an URL structure, you can simply use `strings` or `Hooper`:

```sh
$ strings <yourapp> | grep "myURLscheme://"
```

#### Dynamic Analysis

Once you have identified the custom URL scheme's registered by the app in its `Info.plist`, open the URLs on Safari and observer how the app behaves.

If parts of the URL are parsed by the app, you can perform input fuzzing to detect memory corruption bugs. To do it you may use [IDB](http://www.idbtool.com/) tool:

- Connect IDB tool with your device and select tested application. You can find a detailed guide how to do it in the [IDB documentation](http://www.idbtool.com/documentation/setup.html). 
- Go to `URL Handlers` section. In `URL schemes` click `Refresh` button and you will find on the left a list of all custom schemes defined in tested application. You can load those schemes using `Open` button on the right side. By simply opening blank URI scheme (e.g. open `myURLscheme://`) you may discover hidden functionality (e.g. debug window) or bypass local authentication.
- To find out if custom URI schemes contain any bugs you should try to fuzz them. In `URL Handlers` section go to `Fuzzer` tab. On left side are listed default IDB payloads. The [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) project offers useful fuzzing dictionaries. Once your payload list is ready go to `Fuzz Template` section in the left bottom panel and define a template. Use `$@$` to define an injection point, for example:

```sh
myURLscheme://$@$
```

While the URL scheme is being fuzzed, watch the logs (in Xcode go to `Window -> Devices ->` *click on your device* `->` *bottom console contains logs*) to observe an impact of each payload. On the right side of IDB `Fuzzer` tab, you can see a history of used payloads.

#### Remediation

You should carefully validate any URL, before calling it. You can white-list applications which may be opened via the registered protocol handler. Another helpful control is prompting a user for confirming the action, invoked by an URL.

#### References

##### OWASP Mobile Top 10 2016
- M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."

##### CWE
- CWE-939: Improper Authorization in Handler for Custom URL Scheme

##### Tools
- IDB - http://www.idbtool.com/


### Testing iOS WebViews

#### Overview

WebViews are in-app browser components for displaying interactive web content. They can be used to embed web content directly into an app's user interface. 

iOS WebViews support execution of JavaScript by default, so they can be affected by script injection and cross-site scripting attacks. Starting from iOS version 7.0, Apple also introduced APIs that enable communication between the JavaScript runtime in the WebView and the native Swift or Objective-C app. If these APIs are used carelessly, important functionality might be exposed to attackers if that manage to inject malicious script into the WebView (e.g through a successful cross-site scripting attack).

Besides the potential for script injection, there is another fundamental security issue related to WebViews: The WebKit libraries packaged with iOS do not get updated out-of-band like the Safari web browser. Therefore, any newly discovered WebKit vulnerabilities remain exploitable until the next full iOS update [#THIEL].

#### Static Analysis

WebViews can be implemented using the following components:

- [UIWebView](https://developer.apple.com/reference/uikit/uiwebview "UIWebView reference documentation") (for iOS versions 7.1.2 and older)
- [WKWebView](https://developer.apple.com/reference/webkit/wkwebview "WKWebView reference documentation") (for iOS in version 8.0 and later). 
- [SFSafariViewController](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)

`UIWebView` is deprecated and should not be used. Verify that either WKWebView or SafariViewController are used to embed web content depending on the scenario:

- `WKWebView` is the appropriate choice if the goal is to extend the functionality of the app, content is displayed in a controlled fashion (i.e. the user is not meant to navigate to arbitrary URLs), and customization is required.
- `SafariViewController` should be used when the goal is to provide a provide a generalized web viewing experience. Note that `SafariViewController` shares cookies and other website data with Safari. 

Compared the `UIWebView`, `WKWebView` comes with several security advantages:

- The `JavaScriptEnabled` property can be used to completely disable JavaScipt in the WKWebView. This prevents any kind of script injection flaws. 
- The `JavaScriptCanOpenWindowsAutomatically` can be used to prevent opening of new windows from JavaScript. This prevents JavaScript code from opening irritating pop-up windows from opening.
- the `hasOnlySecureContent` property can be used to verify that all resources loaded by the WebView have been retrieved through encrypted connections.
- WKWebView implements out-of-process rendering, so any memory corruption bugs won't affect the main app process.

As a best practice, JavaScript should be disabled in a `WKWebView` unless explicitly required. The following code sample shows a sample configuration.

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

##### Exposure of Native Objects

Both `UIWebView` and `WKWebView` provide a means of communication between the WebView and the native app. Any important data or native functionality exposed to the WebView JavaScript engine would also be accessible to rogue JavaScript running in the WebView. 

###### UIWebView

Since iOS 7, the JavaScriptCore framework provides an Objective-C wrapper to the WebKit JavaScript engine. This makes it possible to execute JavaScript from Swift and Objective-C, as well as making Objective-C and Swift objects accessible from the JavaScript runtime.

A JavaScript execution environment is represented by a `JSContext` object. Look out for code that maps native objects to the `JSContext` associated with a WebView. In Objective-C, the `JSContext` associated with a `UIWebView` is obtained as follows:

``objective-c
[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]
``

- Objective-C blocks. When an Objective-C block is assigned to an identifier in a JSContext, JavaScriptCore automatically wraps the block in a JavaScript function.

- JSExport protocol: Properties, instance methods, and class methods declared in an JSExport-inherited protocol are mapped to JavaScript objects that are made available to any JavaScript code. Modifications made to the objects in the JavaScript environment are reflected in the native environment.

Note that only class members defined in the `JSExport` protocol only members are made accessible to JavaScript code.

###### WKWebView

In contrast to `UIWebView`, it is not possible to directly reference the `JSContext` of a `WKWebView`. Instead, communication is implemented using a messaging system. JavaScript code can send messages back to the native app using the 'postMessage' method:


```javascript
window.webkit.messageHandlers.myHandler.postMessage()
````

The `postMessage` API automatically serializes JavaScript objects into native Objective-C or Swift objects. Message Handler are configured using the `addScriptMessageHandler` method.


##### Local File Inclusion

WebViews can load content remotely, but can also load it locally from the app data directory. If the content is loaded locally it should not be possible by the user to influence the filename or path where the file is loaded from or should be able to edit the loaded file.

Check the source code for the usage of WebViews. If a WebView instance can be identified check if any local files are loaded ("example_file.html" in the below example).

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

The `baseURL` should be checked, if any dynamic parameters are used that can be manipulated, which may lead to local file inclusion.

#### Dynamic Analysis

To simulate an attack, inject your own JavaScript into the WebView using an interception proxy. Attempt to access local storage and any native methods and properties that might be exposed to the JavaScript context.

In a real-world scenario, JavaScript would have to be injected either through a permanent Cross-Site Scripting vulnerability on the back end, or through a man-in-the-middle attack. See the OWASP [XSS cheat sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting\)\_Prevention_Cheat_Sheet "XSS (Cross Site Scripting) Prevention Cheat Sheet") and the chapter "Testing Network Communication" for more information.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Client Side Injection - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.5: "JavaScript is disabled in WebViews unless explicitly required."

##### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### Info

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition. 

