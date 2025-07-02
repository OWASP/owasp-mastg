---
title: Cycript
platform: ios
source: https://www.cycript.org/
status: deprecated
deprecation_note: Cycript is no longer actively maintained and fails on modern iOS versions. It last saw meaningful updates between 2009 and 2013. Key components like cynject broke on iOS 12 around 2019 due to changes in Cydia Substrate and have not been fixed. Frida offers broader compatibility, active support, and more powerful dynamic instrumentation capabilities.
covered_by: [MASTG-TOOL-0039]
---

Cycript is a scripting language developed by Jay Freeman (aka Saurik). It injects a JavaScriptCore virtual machine into a running process. Using the Cycript interactive console, users can manipulate the process with a hybrid Objective-C++ and JavaScript syntax. Accessing and instantiating Objective-C classes inside a running process is supported. Cycript can be injected into a running process, similar to a debugger, using [Cydia Substrate](http://www.cydiasubstrate.com/), which is the standard framework for developing @MASTG-TOOL-0047 runtime patches known as Cydia Substrate Extensions on iOS. It includes Cynject, a tool that provides code injection support for Cycript.

In order to install Cycript, first download, unpack, and install the SDK.

```bash
#on iphone
$ wget https://cydia.saurik.com/api/latest/3 -O cycript.zip && unzip cycript.zip
$ sudo cp -a Cycript.lib/*.dylib /usr/lib
$ sudo cp -a Cycript.lib/cycript-apl /usr/bin/cycript
```

To spawn the interactive Cycript shell, run "./cycript" or "cycript" if Cycript is on your path.

```bash
$ cycript
cy#
```

To inject into a running process, we first need to find the process ID (PID). Run the application and make sure the app is in the foreground. Running `cycript -p <PID>` injects Cycript into the process. To illustrate, we will inject into SpringBoard (which is always running).

```bash
$ ps -ef | grep SpringBoard
501 78 1 0 0:00.00 ?? 0:10.57 /System/Library/CoreServices/SpringBoard.app/SpringBoard
$ ./cycript -p 78
cy#
```

One of the first things you can try out is to get the application instance (`UIApplication`), you can use Objective-C syntax:

```bash
cy# [UIApplication sharedApplication]
cy# var a = [UIApplication sharedApplication]
```

Use that variable now to get the application's delegate class:

```bash
cy# a.delegate
```

Let's try to trigger an alert message on SpringBoard with Cycript.

```bash
cy# alertView = [[UIAlertView alloc] initWithTitle:@"OWASP MASTG" message:@"Mobile Application Security Testing Guide"  delegate:nil cancelButtonitle:@"OK" otherButtonTitles:nil]
#"<UIAlertView: 0x1645c550; frame = (0 0; 0 0); layer = <CALayer: 0x164df160>>"
cy# [alertView show]
cy# [alertView release]
```

<img src="Images/Chapters/0x06c/cycript_sample.png" width="300px" />

Find the app's document directory with Cycript:

```bash
cy# [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask][0]
#"file:///var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35212DF/Documents/"
```

The command `[[UIApp keyWindow] recursiveDescription].toString()` returns the view hierarchy of `keyWindow`. The description of every subview and sub-subview of `keyWindow` is shown. The indentation space reflects the relationships between views. For example, `UILabel`, `UITextField`, and `UIButton` are subviews of `UIView`.

```xml
cy# [[UIApp keyWindow] recursiveDescription].toString()
`<UIWindow: 0x16e82190; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x16e80ac0>; layer = <UIWindowLayer: 0x16e63ce0>>
  | <UIView: 0x16e935f0; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x16e93680>>
  |    | <UILabel: 0x16e8f840; frame = (0 40; 82 20.5); text = 'i am groot!'; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8f920>>
  |    | <UILabel: 0x16e8e030; frame = (0 110.5; 320 20.5); text = 'A Secret Is Found In The ...'; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8e290>>
  |    | <UITextField: 0x16e8fbd0; frame = (8 141; 304 30); text = ''; clipsToBounds = YES; opaque = NO; autoresize = RM+BM; gestureRecognizers = <NSArray: 0x16e94550>; layer = <CALayer: 0x16e8fea0>>
  |    |    | <_UITextFieldRoundedRectBackgroundViewNeue: 0x16e92770; frame = (0 0; 304 30); opaque = NO; autoresize = W+H; userInteractionEnabled = NO; layer = <CALayer: 0x16e92990>>
  |    | <UIButton: 0x16d901e0; frame = (8 191; 304 30); opaque = NO; autoresize = RM+BM; layer = <CALayer: 0x16d90490>>
  |    |    | <UIButtonLabel: 0x16e72b70; frame = (133 6; 38 18); text = 'Verify'; opaque = NO; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e974b0>>
  |    | <_UILayoutGuide: 0x16d92a00; frame = (0 0; 0 20); hidden = YES; layer = <CALayer: 0x16e936b0>>
  |    | <_UILayoutGuide: 0x16d92c10; frame = (0 568; 0 0); hidden = YES; layer = <CALayer: 0x16d92cb0>>`
```

You can also use Cycript's built-in functions such as `choose` which searches the heap for instances of the given Objective-C class:

```bash
cy# choose(SBIconModel)
[#"<SBIconModel: 0x1590c8430>"]
```

Learn more in the [Cycript Manual](http://www.cycript.org/manual/ "Cycript Manual").
