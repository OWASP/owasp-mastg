---
masvs_v1_id:
- MSTG-PLATFORM-5
masvs_v2_id:
- MASVS-PLATFORM-2
platform: ios
title: Testing iOS WebViews
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

For the static analysis we will focus mostly on the following points having `UIWebView` and `WKWebView` under scope.

- Identifying WebView usage
- Testing if JavaScript is Enabled
- Testing for Mixed Content
- Testing for WebView URI Manipulation

### Identifying WebView Usage

Look out for usages of the above mentioned WebView classes by searching in Xcode.

In the compiled binary you can search in its symbols or strings, for example using @MASTG-TOOL-0129 like this:

#### UIWebView

```bash
$ rabin2 -zz ./WheresMyBrowser | egrep "UIWebView$"
489 0x0002fee9 0x10002fee9   9  10 (5.__TEXT.__cstring) ascii UIWebView
896 0x0003c813 0x0003c813  24  25 () ascii @_OBJC_CLASS_$_UIWebView
1754 0x00059599 0x00059599  23  24 () ascii _OBJC_CLASS_$_UIWebView
```

#### WKWebView

```bash
$ rabin2 -zz ./WheresMyBrowser | egrep "WKWebView$"
490 0x0002fef3 0x10002fef3   9  10 (5.__TEXT.__cstring) ascii WKWebView
625 0x00031670 0x100031670  17  18 (5.__TEXT.__cstring) ascii unwindToWKWebView
904 0x0003c960 0x0003c960  24  25 () ascii @_OBJC_CLASS_$_WKWebView
1757 0x000595e4 0x000595e4  23  24 () ascii _OBJC_CLASS_$_WKWebView
```

Alternatively you can also search for known methods of these WebView classes. For example, search for the method used to initialize a WKWebView ([`init(frame:configuration:)`](https://developer.apple.com/documentation/webkit/wkwebview/1414998-init "WKWebView init(frame:configuration:)")):

```bash
$ rabin2 -zzq ./WheresMyBrowser | egrep "WKWebView.*frame"
0x5c3ac 77 76 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfC
0x5d97a 79 78 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
0x6b5d5 77 76 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfC
0x6c3fa 79 78 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
```

You can also demangle it:

```bash
$ xcrun swift-demangle __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO

---> @nonobjc __C.WKWebView.init(frame: __C_Synthesized.CGRect,
                                configuration: __C.WKWebViewConfiguration) -> __C.WKWebView
```

### Testing if JavaScript is Enabled

First of all, remember that JavaScript cannot be disabled for `UIWebView`s.

For `WKWebView`s, as a best practice, JavaScript should be disabled unless it is explicitly required. To verify that JavaScript was properly disabled search the project for usages of `WKPreferences` and ensure that the [`javaScriptEnabled`](https://developer.apple.com/documentation/webkit/wkpreferences/1536203-javascriptenabled "WKPreferences javaScriptEnabled") property is set to `false`:

```default
let webPreferences = WKPreferences()
webPreferences.javaScriptEnabled = false
```

If only having the compiled binary you can search for this in it using @MASTG-TOOL-0129:

```bash
$ rabin2 -zz ./WheresMyBrowser | grep -i "javascriptenabled"
391 0x0002f2c7 0x10002f2c7  17  18 (4.__TEXT.__objc_methname) ascii javaScriptEnabled
392 0x0002f2d9 0x10002f2d9  21  22 (4.__TEXT.__objc_methname) ascii setJavaScriptEnabled:
```

If user scripts were defined, they will continue running as the `javaScriptEnabled` property won't affect them. See [`WKUserContentController`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller "WKUserContentController") and [WKUserScript](https://developer.apple.com/documentation/webkit/wkuserscript "WKUserScript") for more information on injecting user scripts to WKWebViews.

### Testing for Mixed Content

In contrast to `UIWebView`s, when using `WKWebView`s it is possible to detect [mixed content](https://developers.google.com/web/fundamentals/security/prevent-mixed-content/fixing-mixed-content?hl=en "Preventing Mixed Content") (HTTP content loaded from a HTTPS page). By using the method [`hasOnlySecureContent`](https://developer.apple.com/documentation/webkit/wkwebview/1415002-hasonlysecurecontent "WKWebView hasOnlySecureContent") it can be verified whether all resources on the page have been loaded through securely encrypted connections. This example from [#thiel2] (see page 159 and 160) uses this to ensure that only content loaded via HTTPS is shown to the user, otherwise an alert is displayed telling the user that mixed content was detected.

In the compiled binary you can use @MASTG-TOOL-0129:

```bash
$ rabin2 -zz ./WheresMyBrowser | grep -i "hasonlysecurecontent"

# nothing found
```

In this case, the app does not make use of this.

In addition, if you have the original source code or the IPA, you can inspect the embedded HTML files and verify that they do not include mixed content. Search for `http://` in the source and inside tag attributes, but remember that this might give false positives as, for example, finding an anchor tag `<a>` that includes a `http://` inside its `href` attribute does not always present a mixed content issue. Learn more about mixed content in the [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content "Mixed Content").

### Testing for WebView URI Manipulation

Make sure that the WebView's URI cannot be manipulated by the user in order to load other types of resources than necessary for the functioning of the WebView. This can be specifically dangerous when the WebView's content is loaded from the local file system, allowing the user to navigate to other resources within the application.

## Dynamic Analysis

For the dynamic analysis we will address the same points from the static analysis.

- Enumerating WebView Instances
- Testing if JavaScript is Enabled
- Testing for Mixed Content

It is possible to identify WebViews and obtain all their properties on runtime by performing dynamic instrumentation. This is very useful when you don't have the original source code.

For the following examples, we will keep using the ["Where's My Browser?"](https://github.com/authenticationfailure/WheresMyBrowser.iOS/ "Where\'s My Browser? GitHub Repository") app and Frida REPL.

### Enumerating WebView Instances

Once you've identified a WebView in the app, you may inspect the heap in order to find instances of one or several of the WebViews that we have seen above.

For example, if you use Frida you can do so by inspecting the heap via "ObjC.choose()"

```javascript
ObjC.choose(ObjC.classes['UIWebView'], {
  onMatch: function (ui) {
    console.log('onMatch: ', ui);
    console.log('URL: ', ui.request().toString());
  },
  onComplete: function () {
    console.log('done for UIWebView!');
  }
});

ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('URL: ', wk.URL().toString());
  },
  onComplete: function () {
    console.log('done for WKWebView!');
  }
});

ObjC.choose(ObjC.classes['SFSafariViewController'], {
  onMatch: function (sf) {
    console.log('onMatch: ', sf);
  },
  onComplete: function () {
    console.log('done for SFSafariViewController!');
  }
});
```

For the `UIWebView` and `WKWebView` WebViews we also print the associated URL for the sake of completion.

In order to ensure that you will be able to find the instances of the WebViews in the heap, be sure to first navigate to the WebView you've found. Once there, run the code above, e.g. by copying into the Frida REPL:

```javascript
$ frida -U com.authenticationfailure.WheresMyBrowser

# copy the code and wait ...

onMatch:  <UIWebView: 0x14fd25e50; frame = (0 126; 320 393);
                autoresize = RM+BM; layer = <CALayer: 0x1c422d100>>
URL:  <NSMutableURLRequest: 0x1c000ef00> {
  URL: file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
          Library/UIWebView/scenario1.html, Method GET, Headers {
    Accept =     (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    );
    "Upgrade-Insecure-Requests" =     (
        1
    );
    "User-Agent" =     (
        "Mozilla/5.0 (iPhone; CPU iPhone ... AppleWebKit/604.3.5 (KHTML, like Gecko) Mobile/..."
    );
} }
```

Now we quit with `q` and open another WebView (`WKWebView` in this case). It also gets detected if we repeat the previous steps:

```javascript
$ frida -U com.authenticationfailure.WheresMyBrowser

# copy the code and wait ...

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>
URL:  file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
            Library/WKWebView/scenario1.html
```

We will extend this example in the following sections in order to get more information from the WebViews. We recommend to store this code to a file, e.g. webviews_inspector.js and run it like this:

```javascript
frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js
```

### Checking if JavaScript is Enabled

Remember that if a `UIWebView` is being used, JavaScript is enabled by default and there's no possibility to disable it.

For `WKWebView`, you should verify if JavaScript is enabled. Use [`javaScriptEnabled`](https://developer.apple.com/documentation/webkit/wkpreferences/1536203-javascriptenabled "WKPreferences javaScriptEnabled") from `WKPreferences` for this.

Extend the previous script with the following line:

```javascript

ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('javaScriptEnabled:', wk.configuration().preferences().javaScriptEnabled());
//...
  }
});

```

The output shows now that, in fact, JavaScript is enabled:

```bash

$ frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>

javaScriptEnabled:  true

```

### Testing for Mixed Content

The `UIWebView` class does not provide a method for verifying that only secure content is allowed. However, [starting on iOS 10](https://developer.apple.com/documentation/safari-technology-preview-release-notes/stp-release-7), the [`Upgrade-Insecure-Requests`](https://w3c.github.io/webappsec-upgrade-insecure-requests/#upgrade-insecure-requests) CSP (Content Security Policy) directive was introduced to WebKit, the browser engine powering the iOS WebViews. This directive can be used to instruct the browser to upgrade insecure requests to secure requests. This is a good practice to prevent mixed content issues.

For `WKWebView`'s, you may call the method [`hasOnlySecureContent`](https://developer.apple.com/documentation/webkit/wkwebview/1415002-hasonlysecurecontent "WKWebView hasOnlySecureContent") for each of the `WKWebView`s found in the heap. Remember to do so once the WebView has loaded.

Extend the previous script with the following line:

```javascript
ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('hasOnlySecureContent: ', wk.hasOnlySecureContent().toString());
    //...
      }
    });
```

The output shows that some of the resources on the page have been loaded through insecure connections:

```bash
$ frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>

hasOnlySecureContent:  false
```
