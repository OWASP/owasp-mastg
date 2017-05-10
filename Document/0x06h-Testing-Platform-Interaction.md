## Testing Platform Interaction

### Testing App permissions

#### Overview

-- TODO [Provide a general description of the issue "Testing App permissions".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on Static analysis of "Testing App permissions" with source code] --

##### Without Source Code

-- TODO [Add content on Static analysis of "Testing App permissions" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing App permissions" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing App permissions".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing App permissions"] --

##### OWASP MASVS

- V6.1: "The app only requires the minimum set of permissions necessary."

##### CWE

-- TODO [Add relevant CWE for "Testing App permissions"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add tools for "Testing App permissions"] --


### Testing Input Validation and Sanitization

#### Overview

-- TODO [Provide a general description of the issue "Testing Input Validation and Sanitization".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content for static analysis of "Testing Input Validation and Sanitization" with source code] --

##### Without Source Code

-- TODO [Add content for static analysis of "Testing Input Validation and Sanitization" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Input Validation and Sanitization".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing Input Validation and Sanitization"] --

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

-- TODO [Add relevant CWE for "Testing Input Validation and Sanitization"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing Input Validation and Sanitization"] --


### Testing Custom URL Schemes

#### Overview

-- TODO [Provide a general description of the issue "Testing Custom URL Schemes".]

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on static analysis for "Testing Custom URL Schemes" with source code] --

##### Without Source Code

-- TODO [Add content on static analysis for "Testing Custom URL Schemes" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Custom URL Schemes" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Custom URL Schemes".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing Custom URL Schemes"] --

##### OWASP MASVS

- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."

##### CWE

-- TODO [Add relevant CWE for "Testing Custom URL Schemes"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing Custom URL Schemes"] --


### Testing for Sensitive Functionality Exposed Through IPC

#### Overview

-- TODO [Provide a general description of the issue "Testing for Sensitive Functionality Exposed Through IPC".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on static analysis of "Testing for Sensitive Functionality Exposed Through IPC" with source code] --

##### Without Source Code

-- TODO [Add content on static analysis of "Testing for Sensitive Functionality Exposed Through IPC" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing for Sensitive Functionality Exposed Through IPC" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Sensitive Functionality Exposed Through IPC".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing for Sensitive Functionality Exposed Through IPC"] --

##### OWASP MASVS

- V6.4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."

##### CWE

-- TODO [Add relevant CWE for "Testing for Sensitive Functionality Exposed Through IPC"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing for Sensitive Functionality Exposed Through IPC"] --


### Testing JavaScript Execution in WebViews

#### Overview

The WebView object is used to embed a web browser in your iOS application. It is a convinient way to display a web page in your application without any interaction with your native mobile browser. WebView even allows you to interact with JavaScript code in pages it has loaded. This great opportunity however may expose your application for a big risk if no security controls are applied. One of such big risk is a possibility to execute a malicious JavaScript code in your application via WebView object.

#### Static Analysis

Depending on your iOS version a WebView object can be implemented using UIWebView (for iOS versions 7.1.2 and older)<sup>[1]</sup> or WKWebView (for iOS in version 8.0 and later)<sup>[2]</sup>. WKWebView is recommended to be used. 

##### With Source Code

The WKWebView object allows for JavaScript execution by default. That may raise a serious risk of running arbitrary code on user's device via WebView object. If your application does not require executing JavaScript (just display a web page), you should definitely disable it. You can do it using preferences of an object WKPreferences<sup>[3]</sup>, like in the following example:

```
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

If there is no explicitly disabled JavaScript execution via WKPreferences object, then it means it is enabled.


#### Dynamic Analysis

A Dynamic Analysis depends on different surrounding conditions, as there are different possibilities to inject JavaScript into a WebView of an application:

* Stored Cross-Site Scripting (XSS) vulnerability in an endpoint, where the exploit will be sent to the WebView of the Mobile App when navigating to the vulnerable function.
* Man-in-the-middle (MITM) position by an attacker where he is able to tamper the response by injecting JavaScript.

#### Remediation

The UIWebView should be avoided and WKWebView used instead. JavaScript is enabled by default in a WKWebView and should be disabled if not needed. This reduces the attack surface and potential threats to the application. If JavaScript is needed it should be ensured:

In order to address these attack vectors, the outcome of the following checks should be verified:

* that all functions offered by the endpoint need to be free of XSS vulnerabilities<sup>[4]</sup>.
 
* that the HTTPS communication need to be implemented according to the best practices to avoid MITM attacks (see "Testing Network Communication").


#### References

##### OWASP Mobile Top 10 2014

* M7 - Client Side Injection

##### OWASP MASVS

- V6.5: "JavaScript is disabled in WebViews unless explicitly required."

##### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### Info

- [1] UIWebView reference documentation - https://developer.apple.com/reference/uikit/uiwebview
- [2] WKWebView reference documentation - https://developer.apple.com/reference/webkit/wkwebview
- [3] WKPreferences - https://developer.apple.com/reference/webkit/wkpreferences#//apple_ref/occ/instp/WKPreferences/javaScriptEnabled
- [4] XSS (Cross Site Scripting) Prevention Cheat Sheet - https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet


### Testing WebView Protocol Handlers

#### Overview

-- TODO [Provide a general description of the issue "Testing WebView Protocol Handlers".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on static analysis of "Testing WebView Protocol Handlers" with source code) --

##### Without Source Code

-- TODO [Add content on static analysis of "Testing WebView Protocol Handlers" without source code) --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing WebView Protocol Handlers" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing WebView Protocol Handlers".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing WebView Protocol Handlers"] --

##### OWASP MASVS

- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."

##### CWE

-- TODO [Add relevant CWE for "Testing WebView Protocol Handlers"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing WebView Protocol Handlers"] --


### Testing for Local File Inclusion in WebViews

#### Overview

-- TODO [Provide a general description of the issue "Testing for Local File Inclusion in WebViews".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on static analysis of "Testing for Local File Inclusion in WebViews" with source code] --

##### Without Source Code

-- TODO [Add content on static analysis of "Testing for Local File Inclusion in WebViews" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing for Local File Inclusion in WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Local File Inclusion in WebViews".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014] --

##### OWASP MASVS

- V6.7: "The app does not load user-supplied local resources into WebViews."

##### CWE

-- TODO [Add relevant CWE for "Testing for Local File Inclusion in WebViews"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing for Local File Inclusion in WebViews"] --


### Testing Whether Java Objects Are Exposed Through WebViews

#### Overview

-- TODO [Provide a general description of the issue "Testing Whether Java Objects Are Exposed Through WebViews".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content for static analysis of "Testing Whether Java Objects Are Exposed Through WebViews" with source code] --

##### Without Source Code

-- TODO [Add content for static analysis of "Testing Whether Java Objects Are Exposed Through WebViews" with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Whether Java Objects Are Exposed Through WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Whether Java Objects Are Exposed Through WebViews".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing Whether Java Objects Are Exposed Through WebViews"] --

##### OWASP MASVS

- V6.8: "If Java objects are exposed in a WebView, verify that the WebView only renders JavaScript contained within the app package."

##### CWE

-- TODO [Add relevant CWE for "Testing Whether Java Objects Are Exposed Through WebViews"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing Whether Java Objects Are Exposed Through WebViews"] --


### Testing Object Serialization

#### Overview

-- TODO [Add overview for "Testing Object Serialization"] --


#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on static analysis of "Testing Object Serialization" with source code] --

##### Without Source Code

-- TODO [Add content on static analysis of "Testing Object Serialization" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Object Serialization" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Object Serialization".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014] --

##### OWASP MASVS

- V6.9: "Object serialization, if any, is implemented using safe serialization APIs."

##### CWE

-- TODO [Add relevant CWE for "Testing Object Serialization"] --

##### Info

- [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html


##### Tools

-- TODO [Add relevant tools for "Testing Object Serialization"] --


### Testing Jailbreak Detection

#### Overview

iOS implements containerization so that each app is restricted to its own sandbox. A regular app cannot access files outside its dedicated data directories, and access to system APIs is restricted via app privileges. As a result, an app’s sensitive data as well as the integrity of the OS is guaranteed under normal conditions. However, when an adversary gains root access to the mobile operating system, the default protections can be bypassed completely.

The risk of malicious code running as root is higher on jailbroken devices, as many of the default integrity checks are disabled. Developers of apps that handle highly sensitive data should therefore consider implementing checks that either prevent the app from running under these conditions, or at least warn the user about the increased risks.

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### With Source Code

-- TODO [Add content on static analysis of "Testing Jailbreak Detection" with source code] --

##### Without Source Code

-- TODO [Add content on static analysis of "Testing Jailbreak Detection" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Jailbreak Detection" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Jailbreak Detection".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014] --

##### OWASP MASVS

- V6.10: "The app detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users are warned, or the app is terminated if the device is rooted or jailbroken."

##### CWE

-- TODO [add relevant CWE for "Testing Jailbreak Detection"] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add relevant tools for "Testing Jailbreak Detection"] --
