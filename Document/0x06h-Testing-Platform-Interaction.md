## iOS Platform APIs

### Testing App Permissions

#### Overview
iOS makes all mobile applications run under the `mobile` user. Each application is sandboxed and limited using policies enforced by the Trusted BSD mandatory access control framework. These policies are called profiles and all third-party applications use on generic sandbox profile: the container permission list. See the [archived Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AppSandboxInDepth/AppSandboxInDepth.html "Apple Developer Documentation on Sandboxing") and the [newer Apple Developer Security Documentation](https://developer.apple.com/documentation/security "Apple Developer Security Documentation") for more details.

On iOS, apps need to request permission to the user for accessing one of the following data or resources:
- Bluetooth peripherals,
- Calendar data,
- Camera,
- Contacts,
- Health sharing,
- Health updating,
- HomeKit,
- Location,
- Microphone,
- Motion,
- Music and the media library,
- Photos,
- Reminders,
- Siri,
- Speech recognition,
- the TV provider.
For more details, check the [Archived App Programming Guide for iOS](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Data and resources protected by system authorization settings") and the article [Protecting the User's Privacy at Apples Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy "Protecting the User's Privacy")
Even though Apple urges to protect the privacy of the user and be [very clear on how to ask permissions](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Requesting Permissions"), it can still be the case that an app requests too many permissions.

Next to the resources for which permission is requested there is a set of capabilities, which can be required by the app developer in order to run the device. These capabilities (`UIRequiredDeviceCapabilities`) are listed at the [Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW1 "UIRequiredDeviceCapabilities"). These capabilities are used by App Store and by iTunes to ensure that only compatible devices are listed. Many of these capabilities do not require the user to provide permission. Note that the actual available capabilities differ per type of developer profile used to sign the application. See [the Apple Developer Documentation](https://developer.apple.com/support/app-capabilities/ "Advanced App Capabilities") for more details.

#### Static analysis

Since iOS 10, there are three areas which you need to inspect for permssions:
- the Info.plist file,
- the `<appname>.enttitlements` file, where <appname> is the name of the application
- the source-code.

##### Info.plist
The Info.plist contains the texts offered to users when requesting permissioin to access the protected data or resources. The [Apple Documentation](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Requesting Permission") gives a clear instruction on how the user should be asked for permission to access the given resource. Following these guidelines should make it relatively simple to evaluate each and every entry in the Info.plist file to check if the permission makes sense.
For example, when you have a Info.plist file, for a Solitair game which has, at least, the following content:

```xml
<key>NSHealthClinicalHealthRecordsShareUsageDescription</key>
<string>Share your health data with us!</string>
<key>NSCameraUsageDescription</key>
<string>We want to access your camera</string>
```
Should be suspicious as a normal solitair game probably does not have any need for accessing the camera nor a user's health-records.
Note that from iOS 10 onward you need to provide explanation in terms of these \*Description fields. See table 1-2 at the [Apple app programming guide](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Apple app programming guide") for a more complete overview of different keys to look for.

##### Entitlements file
The entitlements file shows which capabilities are used. Some of these capabilities do not need any additional permissions provided by the user, but can still leak information to other apps. Take the App Groups capability for instance. As documented at [Apple Developer documentation](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html "Handling Common Scenarios") and [App Groups Entitlement](https://developer.apple.com/documentation/foundation/com_apple_security_application-groups?changes=_5&language=objc "Appl Groups Entitlement"). With this capability, one can share information between different apps through IPC or a shared file container, which means that data can be shared on the device directly between the apps. Here is an example of an application entitlement file with the app-group capability:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
  <!-- Note: this array contains all the capabilities registered for the app. -->
  <array/>
</dict>
</plist>
```

Note that this requirement is not always necessary to "bleed" information from one application to another. You can have a back-end as a medium between two applications to share information as well.

##### Source code inspection
After having checked the <appname>.entitlements file and the Info.plist file, it is time to verify how the requested permissions and assigned capabilities are put to use. For this, a source code-review should be enough.
Pay attention to:
- whether the permission explanation in the Info.plist file matches the programmatic implementation.
- whether the capabilities registered are used in such a way that no confidential information is leaking.

Note that apps should crash if a capability is requried to use which requires a permission without the permission-explanation-text being registered at the Info.plist file.

#### Dynamic Analysis
There are various steps in the analysis process:
- Check the embedded.mobileprovision file and the <appname>.entitlements file and see which capbilities they contain.
- Obtain the Info.plist file and check for which permissions it provided an explanation.
- Go through the application and check whether the application communicates with other applications or with back-ends. Check whether the information retrieved using the permissions and capbilities are used for ill-purposed or are over-asked/under-utilized.


### Testing Custom URL Schemes

#### Overview

In contrast to Android's rich Inter-Process Communication (IPC) capability, iOS offers few options for communication between apps. In fact, there's no way for apps to communicate directly. Instead, Apple offers [two types of indirect communication](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html "Inter-App Communication"): file transfer through AirDrop and custom URL schemes.

Custom URL schemes allow apps to communicate via a custom protocol. An app must declare support for the scheme and handle incoming URLs that use the scheme. Once the URL scheme is registered, other apps can open the app that registered the scheme, and pass parameters by creating appropriately formatted URLs and opening them with the `openURL` method.

Security issues arise when an app processes calls to its URL scheme without properly validating the URL and its parameters and when users aren't prompted for confirmation before triggering an important action.

One example is the following [bug in the Skype Mobile app](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html), discovered in 2010: The Skype app registered the `skype://` protocol handler, which allowed other apps to trigger calls to other Skype users and phone numbers. Unfortunately, Skype didn't ask users for permission before placing the calls, so any app could call arbitrary numbers without the user's knowledge.

Attackers exploited this vulnerability by putting an invisible `<iframe src="skype://xxx?call"></iframe>` (where `xxx` was replaced by a premium number), so any Skype user who inadvertently visited a malicious website called the premium number.

#### Static Analysis

The first step to test custom URL schemes is finding out whether an application registers any protocol handlers. This information is in the file `Info.plist` in the application sandbox folder. To view registered protocol handlers, simply open a project in Xcode, go to the `Info` tab, and open the `URL Types` section, presented in the screenshot below.

![Document Overview](Images/Chapters/0x06h/URL_scheme.png)

Next, determine how a URL path is built and validated. The method [`openURL`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc) is responsible for handling user URLs. Look for implemented controls: how URLs are validated (the input it accepts) and whether it needs user permission when using the custom URL schema?

In a compiled application, registered protocol handlers are found in the file `Info.plist`. To find a URL structure, look for uses of the `CFBundleURLSchemes` key using `strings` or `Hopper`:

```sh
$ strings <yourapp> | grep "myURLscheme://"
```

You should carefully validate any URL before calling it. You can whitelist applications which may be opened via the registered protocol handler. Prompting users to confirm the URL-invoked action is another helpful control.

#### Dynamic Analysis

Once you've identified the custom URL schemes the app has registered, open the URLs on Safari and observe how the app behaves.

If the app parses parts of the URL, you can perform input fuzzing to detect memory corruption bugs. For this you can use [IDB](https://www.idbtool.com/):

- Start IDB, connect to your device and select the target app. You can find details in the [IDB documentation](https://www.idbtool.com/documentation/setup.html).
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

### Testing WebView Protocol Handlers

#### Overview

Several default schemas are available that are being interpreted in a WebViews. The following schemas can be used within a WebView on iOS:

-	http(s)://
-	file://
-	tel://

WebViews can load remote content from an endpoint, but they can also load local content from the app data directory. If the local content is loaded, the user shouldn't be able to influence the filename or the path used to load the file, and users shouldn't be able to edit the loaded file.

#### Static Analysis

Check the source code for WebView usage. The following WebView settings control resource access:

- `allowFileAccessFromFileURLs`
- `allowUniversalAccessFromFileURLs`
- `allowingReadAccessToURL`

Example of setting `allowFileAccessFromFileURLs` in a WebView:

Objective-C:
```objc

[webView.configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];

```

Swift:
```swift

webView.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")

```

By default WKWebView disables file access. If one or more of the above methods is/are activated, you should determine whether the method(s) is/are really necessary for the app to work properly.

Please also verify which WebView class is used. WKWebView should be used nowadays, as `UIWebView` is deprecated.

If a WebView instance can be identified, find out whether local files are loaded with the [`loadFileURL`](https://developer.apple.com/documentation/webkit/wkwebview/1414973-loadfileurl?language=objc "loadFileURL") method.

Objective-C:
```objc

[self.wk_webview loadFileURL:url allowingReadAccessToURL:readAccessToURL];

```

Swift:
```swift

webview.loadFileURL(url, allowingReadAccessTo: bundle.resourceURL!)

```

The URL specified in `loadFileURL` should be checked for dynamic parameters that can be manipulated; their manipulation may lead to local file inclusion.

Detection of the [tel:// schema can be disabled](https://developer.apple.com/library/content/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html "Phone Links on iOS") in the HTML page and will then not be interpreted by the WebView.

Use the following best practices as defensive-in-depth measures:
- Create a whitelist that defines local and remote web pages and schemas that are allowed to be loaded.
- Create checksums of the local HTML/JavaScript files and check them while the app is starting up. Minify JavaScript files to make them harder to read.

#### Dynamic Analysis

To identify the usage of protocol handlers, look for ways to access files from the file system and trigger phone calls while you're using the app.

If it's possible to load local files via a WebView, the app might be vulnerable to directory traversal attacks. This would allow access to all files within the sandbox or even to escape the sandbox with full access to the file system (if the device is jailbroken).  

It should therefore be verified if a user can change the filename or path from which the file is loaded, and they shouldn't be able to edit the loaded file.



### Determining Whether Native Methods Are Exposed Through WebViews

#### Overview

Starting from iOS version 7.0, Apple introduced APIs that allow communication between the JavaScript runtime in the WebView and the native Swift or Objective-C objects. If these APIs are used carelessly, important functionality might be exposed to attackers who manage to inject malicious script into the WebView (e.g., through a successful cross-site scripting attack).

#### Static Analysis

Both `UIWebView` and `WKWebView` provide a means of communication between the WebView and the native app. Any important data or native functionality exposed to the WebView JavaScript engine would also be accessible to rogue JavaScript running in the WebView.

Since iOS 7, the JavaScriptCore framework provides an Objective-C wrapper to the WebKit JavaScript engine. This makes it possible to execute JavaScript from Swift and Objective-C, as well as making Objective-C and Swift objects accessible from the JavaScript runtime. A JavaScript execution environment is represented by a `JSContext` object. Look out for code that maps native objects to the `JSContext` associated with a WebView and analyze what functionality it exposes, for example no sensitive data should be accessible and exposed to WebViews. In Objective-C, the `JSContext` associated with a `UIWebView` is obtained as follows:

```objc

[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]

```

There are two fundamental ways of how native code and JavaScript can communicate:

- **JSContext**: When an Objective-C or Swift block is assigned to an identifier in a JSContext, JavaScriptCore automatically wraps the block in a JavaScript function;
- **JSExport protocol**: Properties, instance methods, and class methods declared in a JSExport-inherited protocol are mapped to JavaScript objects that are available to all JavaScript code. Modifications of objects that are in the JavaScript environment are reflected in the native environment.

Note that only class members defined in the `JSExport` protocol are made accessible to JavaScript code.

#### Dynamic Analysis

Dynamic analysis of the app can show you which HTML or JavaScript files are loaded while using the app. You would need to find all webviews in the iOS app in order to get an overview of the potential attack surface.

Usage of the JSContext and JSExport ideally should be identified through static analysis and also which functions are exposed and present in a webview. The procedure for exploiting the functions starts with producing a JavaScript payload and injecting it into the file that the app is requesting. The injection can be accomplished via a MITM attack. See an example for a vulnerable iOS app and function that is exposed to a webview in [#THIEL] page 156 following.


### Testing iOS WebViews

#### Overview

WebViews are in-app browser components for displaying interactive web content. They can be used to embed web content directly into an app's user interface. iOS WebViews support JavaScript execution by default, so script injection and cross-site scripting attacks can affect them.

#### Static Analysis

Look out for usages of the following classes that implement WebViews:

- [UIWebView](https://developer.apple.com/reference/uikit/uiwebview "UIWebView reference documentation") (for iOS versions 7.1.2 and older)
- [WKWebView](https://developer.apple.com/reference/webkit/wkwebview "WKWebView reference documentation") (for iOS in version 8.0 and later)
- [SFSafariViewController](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)

`UIWebView` is deprecated and should not be used. Make sure that either `WKWebView` or `SafariViewController` are used to embed web content:

- `WKWebView` is the appropriate choice for extending app functionality, controlling displayed content  (i.e., prevent the user from navigating to arbitrary URLs) and customizing.
- `SafariViewController` should be used to provide a generalized web viewing experience.

> Note that `SafariViewController` shares cookies and other website data with Safari.

`WKWebView` comes with several security advantages over `UIWebView`:

- The `JavaScriptEnabled` property can be used to completely disable JavaScript in the WKWebView. This prevents all script injection flaws.
- The `JavaScriptCanOpenWindowsAutomatically` can be used to prevent JavaScript from opening new windows, such as pop-ups.
- the `hasOnlySecureContent` property can be used to verify resources loaded by the WebView are retrieved through encrypted connections.
- WKWebView implements out-of-process rendering, so memory corruption bugs won't affect the main app process.

WKWebView also increases the performance of apps that are using WebViews significantly, through the Nitro JavaScript engine [#THIEL].

##### JavaScript Configuration

As a best practice, disable JavaScript in a `WKWebView` unless it is explicitly required. The following code sample shows a sample configuration.

```objc

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

###### WKWebView

In contrast to `UIWebView`, it is not possible to directly reference the `JSContext` of a `WKWebView`. Instead, communication is implemented using a messaging system. JavaScript code can send messages back to the native app using the 'postMessage' method:

```javascript

window.webkit.messageHandlers.myHandler.postMessage()

````

The `postMessage` API automatically serializes JavaScript objects into native Objective-C or Swift objects. Message Handler are configured using the `addScriptMessageHandler` method.


##### Local File Inclusion

WebViews can load content remotely and locally from the app data directory. If the content is loaded locally, users should not be able to change the filename or path from which the file is loaded, and they shouldn't be able to edit the loaded file.

Check the source code for WebViews usage. If you can identify a WebView instance, check whether any local files have been loaded ("example_file.html" in the below example).

```objc

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

##### `hasOnlySecureContent`

In WKWebViews it is possible to detect mixed content or content that was completely loaded via HTTP. By using the method `hasOnlySecureContent` it can be ensured that only content via HTTPS is show, otherwise an alert is shown to the user, see page 159 and 160 in [#THIEL] for an example.  

#### Dynamic Analysis

To simulate an attack, inject your own JavaScript into the WebView with an interception proxy. Attempt to access local storage and any native methods and properties that might be exposed to the JavaScript context.

In a real-world scenario, JavaScript can only be injected through a permanent backend Cross-Site Scripting vulnerability or a man-in-the-middle attack. See the OWASP [XSS cheat sheet](https://goo.gl/x1mMMj "XSS (Cross Site Scripting) Prevention Cheat Sheet") and the chapter "Testing Network Communication" for more information.

### Testing Object Persistence

#### Overview

There are several ways to persist an object on iOS:

##### Object Encoding
iOS comes with two protocols for object encoding and decoding for Objective-C or NSObjects: `NSCoding` and `NSSecureCoding`. When a class conforms to either of the protocols, the data is serialized to `NSData`: a wrapper for byte buffers. Note that `Data` in Swift is the same as `NSData` or its mutable counterpart: `NSMutableData`. The `NSCoding` protocol declares the two methods that must be implemented in order to encode/decode its instance-variables. A class using NSCoding needs to implement NSObject or be annotated as an @objc class. The NSCoding protocol requires to implement encode and init as shown below.

```swift
class CustomPoint: NSObject, NSCoding {

	//required by NSCoding:
	func encode(with aCoder: NSCoder) {
		aCoder.encode(x, forKey: "x")
		aCoder.encode(name, forKey: "name")
	}

	var x: Double = 0.0
	var name: String = ""

	init(x: Double, name: String) {
			self.x = x
			self.name = name
	}

	// required by NSCoding: initalize members using a decoder.
	required convenience init?(coder aDecoder: NSCoder) {
			guard let name = aDecoder.decodeObject(forKey: "name") as? String
					else {return nil}
			self.init(x:aDecoder.decodeDouble(forKey:"x"),
								name:name)
	}

	//getters/setters/etc.
}
```

The issue with `NSCoding` is that the object is often already constructed and inserted before you can evaluate the class-type. This allows an attacker to easily inject all sorts of data. Therefore, the `NSSecureCoding` protocol has been introduced. When conforming to `NSSecureCoding` you need to include

```swift

static var supportsSecureCoding: Bool {
        return true
}
```

when `init(coder:)` is part of the class. Next, when decoding the object, a check should be made, e.g.:
```Swift
let obj = decoder.decodeObject(of:MyClass.self, forKey: "myKey")
```
*Source: https://developer.apple.com/documentation/foundation/NSSecureCoding*

The conformance to `NSSecureCoding` ensures that objects being instantiated are indeed the ones that were expected. However, there are no additional integrity checks done over the data and the data is not encrypted. Therefore, any secret data needs additional encryption and data of which the integrity must be protected, should get an additional HMAC.

Note, when `NSData` (Objective-c) or the keyword `let` (Swift) is used: then the data is immutable in memory and cannot be easily removed.


##### Object Archiving with NSKeyedArchiver
`NSKeyedArchiver` is a concrete subclass of NSCoder and provides a way to encode objects and store them in a file. The `NSKeyedUnarchiver` decodes the data and recreates the original data. Let's take the example of the `NSCoding` section and now archive and unarchive them:

```swift

//archiving:
NSKeyedArchiver.archiveRootObject(customPoint, toFile: "/path/to/archive")

//unarchiving:
guard let customPoint = NSKeyedUnarchiver.unarchiveObjectWithFile("/path/to/archive") as? CustomPoint else { return nil }

```

When decoding a keyed archive, because values are requested by name, values can be decoded out of sequence or not at all. Keyed archives, therefore, provide better support for forward and backward compatibility. This means that an archive on disk could actually contain addditional data which is not detected by the program, unless the key for that given data is provided at a later stage.

Note that additional protection needs to be in place to secure the file in case of confidential data, as the data is not encrypted within the file. See the Data Storage section for more details.

##### Codable
With Swift 4, the `Codable` type alias arrived: it is a combination of the `Decodable` and `Encodable` protocols. A String, Int, Double, Date, Data and URL are Codable by nature: meaning they can easily be encoded and decoded without any additonal work. Let's take the following example:

```swift
struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}
```

By adding `Codable` to the inheritance list for the `CustomPointStruct` in the example, the methods `init(from:)` and `encode(to:)` are automatically supported. Fore more details about the workings of `Codable` check [the Apple Developer Documentation](https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types "Codable").
The `Codable`s can easily be encoded/decoded into various representations: NSData using `NSCoding`/`NSSecureCoding`, JSON, Property Lists, XML, etc. . See the other subsections of this chapter for more details.

##### JSON and Codable
There are various ways to encode and decode JSON within iOS by using different 3rd party librariesL
- [Mantle](https://github.com/Mantle/Mantle "Mantle"),
- [JSONModel library](https://github.com/jsonmodel/jsonmodel "JSONModel"),
- [SwiftyJSON library](https://github.com/SwiftyJSON/SwiftyJSON "SwiftyJSON"),
- [ObjectMapper library](https://github.com/Hearst-DD/ObjectMapper, "ObjectMapper library"),
- [JSONKit](https://github.com/johnezang/JSONKit "JSONKit"),
- [JSONModel](https://github.com/JSONModel/JSONModel "JSONModel"),
- [YYModel](https://github.com/ibireme/YYModel "YYModel"),
- [SBJson 5](https://github.com/ibireme/YYModel "SBJson 5"),
- [Unbox](https://github.com/JohnSundell/Unbox "Unbox"),
- [Gloss](https://github.com/hkellaway/Gloss "Gloss"),
- [Mapper](https://github.com/lyft/mapper "Mapper"),
- [JASON](https://github.com/delba/JASON "JASON"),
- [Arrow](https://github.com/freshOS/Arrow "Arrow").

The libraries differ in their support for certain versions of Swift and Objective-C, whether they return (im)muttable results, speed, memory consumption and actual library size.
Again, note in case of immutability: confidential information cannot be removed from memory easily.

Next, Apple provides support for JSON encoding/decoding directly by combining `Codable` together with a `JSONEncoder` and a `JSONDecoder`:

```swift
struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}

let encoder = JSONEncoder()
encoder.outputFormatting = .prettyPrinted

let test = CustomPointStruct(x: 10, name: "test")
let data = try encoder.encode(test)
print(String(data: data, encoding: .utf8)!)
// Prints:
// {
//   "x" : 10,
//   "name" : "test"
// }

```

JSON itself can be stored anywhere, e.g., a (NoSQL) database or a file. You just need to make sure that any JSON that contains secrets has been appropriately protected (e.g., encrypted/HMACed). See the data storage chapter for more details.


##### Property Lists and Codable

You can persist objects to `PropertyList`s (also called Plists in previous sections). You can find 2 examples below of how to use it:

```swift

//archiving:
let data = NSKeyedArchiver.archivedDataWithRootObject(customPoint)
NSUserDefaults.standardUserDefaults().setObject(data, forKey: "customPoint")

//unarchiving:

if let data = NSUserDefaults.standardUserDefaults().objectForKey("customPoint") as? NSData {
    let customPoint = NSKeyedUnarchiver.unarchiveObjectWithData(data)
}

```
In this first example, the `NSUserDefaults` are used, which is the primary `PropertyList`. We can do the same with the `Codable` version:

```swift

struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}

var points: [CustomPointStruct] = [
    CustomPointStruct(x: 1, name "test"),
    CustomPointStruct(x: 2, name "test"),
    CustomPointStruct(x: 3, name "test"),
]

UserDefaults.standard.set(try? PropertyListEncoder().encode(points), forKey:"points")
if let data = UserDefaults.standard.value(forKey:"points") as? Data {
    let points2 = try? PropertyListDecoder().decode(Array<CustomPointStruct>.self, from: data)
}

```
Note that PropertyList files are not meant to store secret information. They are designed to hold user-preferences for an app.

##### XML
There are multiple ways to do XML encoding. Similar to JSON parsing, there are various third party libraries, such as:
- [Fuzi](https://github.com/cezheng/Fuzi "Fuzi"),
- [Ono](https://github.com/mattt/Ono "Ono"),
- [AEXML](https://github.com/tadija/AEXML "AEXML"),
- [RaptureXML](https://github.com/ZaBlanc/RaptureXML "RaptureXML"),
- [SwiftyXMLParser](https://github.com/yahoojapan/SwiftyXMLParser "SwiftyXMLParser"),
- [SWXMLHash](https://github.com/drmohundro/SWXMLHash "SWXMLHash").

They vary in terms of speed, memory usage, object persistency and more important: differ in how they handle XML external entities. See [XXE in the Apple iOS Office viewer](https://nvd.nist.gov/vuln/detail/CVE-2015-3784 "CVE-2015-3784") as an example. Therefore, it is key to disable external entity parsing if possible. See the [OWASP XXE prevention cheatsheet](https://goo.gl/86epVd "XXE prevention cheatsheet") for more details.
Next to the libraries, you can make use of Apple's [XMLParser class](https://developer.apple.com/documentation/foundation/xmlparser "XMLParser")

When not using third party libraries, but Apple's `XMLParser`, be sure to let `shouldResolveExternalEntities` return false.

##### ORM (Coredata and Realm)
There are various ORM-like solutiosn for iOS. The first one is [Realm](https://realm.io/docs/swift/latest/ "Realm"), which comes with its own storage engine. Realm has settings to encrypt the data as explained in [Realm's documetation](https://academy.realm.io/posts/tim-oliver-realm-cocoa-tutorial-on-encryption-with-realm/ "Enable encryption"). This allows for handling secure data. Note that the encryption is turned off by default.

Apple itself supplies CoreData. CoreData is well explained in the [Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/index.html#//apple_ref/doc/uid/TP40001075-CH2-SW1, "CoreData"). It supports various storage backends as described in [Apple's PersistentStoreFeatures documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/PersistentStoreFeatures.html "PersistentStoreFeatures"). The issue with the storage backends recommended by Apple, is that none of the type of datastores is encrypted, nor checked for integrity. Therefore, additional actions are necessary in case of confidential data. An alternative can be found in project [iMas](https://github.com/project-imas/encrypted-core-data "Encrypted Core Data"), which does supply out of the box encryption.

#####Protocol Buffers
[Protocol Buffers](https://developers.google.com/protocol-buffers/ "Google Documentation") by Google, are a platform- and language neutral mechanism for serializing structured data by means of the [Binary Data Format](https://developers.google.com/protocol-buffers/docs/encoding "Encoding"). They are available for iOS by means of the [Protobuf](https://github.com/apple/swift-protobuf "Protobuf") library.
There have been a few vulnerabilities with Protocol Buffers, such as [CVE-2015-5237](https://www.cvedetails.com/cve/CVE-2015-5237/ "CVE-2015-5237").
Note that Protocol Buffers do not provide any protection for confidentiality: there is no built in encryption.


#### Static Analysis
All different flavors of object persistence share the following concerns:

- If you use object persistence to store sensitive information on the device, then make sure that the data is encrypted: either at the database level, or specifically at the value level.
- Need to guarantee the integrity of the information? Use an HMAC mechanism or sign the information stored. Always verify the HMAC/signature before processing the actual information stored in the objects.
- Make sure that keys used in the two notions above are safely stored in the KeyChain and well protected. See the Data Storage section for more details.
- Ensure that the data within the de-serialized object is carefully validated before it is actively used (e.g., no exploit of business/application logic).
- Do not use persistence mechanisms that use [Runtime Reference](https://developer.apple.com/library/archive/#documentation/Cocoa/Reference/ObjCRuntimeRef/Reference/reference.html "Objective-C runtime reference") to serialize/deserialize objects in high risk applications, as the attacker might be able to manipulate the steps to execute business logic via this mechanism (See anti-reverse-engineering chapter for more details).
- Note that in Swift 2 and beyond, the [Mirror](https://developer.apple.com/documentation/swift/mirror "Mirror") can be used to read parts of an object, but cannot be used to write against the object.

#### Dynamic Analysis
There are several ways to perform dynamic analysis:

- For the actual persistence: Use the techniques described in the data storage chapter.
- For the serialization itself: use a debug build or use Frida/Objection to see how the serialization methods are handled (e.g., whether the application crashes or extra information can be extracted by enriching the objects).



### References

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition.
- Security Flaw with UIWebView - (https://medium.com/ios-os-x-development/security-flaw-with-uiwebview-95bbd8508e3c "Security Flaw with UIWebView")

#### OWASP Mobile Top 10 2016

- M1 - Improper Platform Usage - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.1: "The app only requests the minimum set of permissions necessary."
- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."
- V6.5: "JavaScript is disabled in WebViews unless explicitly required."
- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."
- V6.7: "If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package."
- V6.8: "Object serialization, if any, is implemented using safe serialization APIs."


#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-200 - Information Leak / Disclosure
- CWE-939 - Improper Authorization in Handler for Custom URL Scheme


#### Tools

- IDB - https://www.idbtool.com/

#### Regarding Object Persistence in iOS
- https://developer.apple.com/documentation/foundation/NSSecureCoding
- https://developer.apple.com/documentation/foundation/archives_and_serialization?language=swift
- https://developer.apple.com/documentation/foundation/nskeyedarchiver
- https://developer.apple.com/documentation/foundation/nscoding?language=swift,https://developer.apple.com/documentation/foundation/NSSecureCoding?language=swift
- https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types
- https://developer.apple.com/documentation/foundation/archives_and_serialization/using_json_with_custom_types
- https://developer.apple.com/documentation/foundation/jsonencoder
- https://medium.com/if-let-swift-programming/migrating-to-codable-from-nscoding-ddc2585f28a4
- https://developer.apple.com/documentation/foundation/xmlparser
