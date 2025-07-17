---
title: ipsw
platform: ios
source: https://github.com/blacktop/ipsw
host:
- windows
- linux
- macOS
---

IPSW calls itself an "iOS/macOS Research Swiss Army Knife". In general, IPSW allows you to obtain iOS specific files (IPSW, OTA, ...) and also statically analyze them. For application analysis, the most interesting features are the Objective-C and Swift class-dumps. Other features are available (kernelcache parser, device-tree parser, disassembler, etc) but are only useful if you're analyzing the security of the OS itself.

## Extracting Objective-C Class Information

IPSW can extract Objective-C class information from a MachO binary. The desired architecture can be specified using `--arch` in case of a universal MachO file:

```bash
$ ipsw class-dump --arch arm64 UnCrackable\ Level\ 1

@protocol NSObject

@required

...

-[UIApplicationDelegate applicationDidFinishLaunching:];
-[UIApplicationDelegate application:willFinishLaunchingWithOptions:];
-[UIApplicationDelegate application:didFinishLaunchingWithOptions:];
-[UIApplicationDelegate applicationDidBecomeActive:];

...
```

??? "Full command output"

    ```bash
    $ ipsw class-dump --arch arm64 UnCrackable\ Level\ 1

    @protocol NSObject

    @required

    @property (TQ,R) hash;
    @property (T#,R) superclass;
    @property (T@"NSString",R,C) description;
    @property (T@"NSString",R,C) debugDescription;

    /* required instance methods */
    -[NSObject isEqual:];
    -[NSObject class];
    -[NSObject self];
    -[NSObject performSelector:];
    -[NSObject performSelector:withObject:];
    -[NSObject performSelector:withObject:withObject:];
    -[NSObject isProxy];
    -[NSObject isKindOfClass:];
    -[NSObject isMemberOfClass:];
    -[NSObject conformsToProtocol:];
    -[NSObject respondsToSelector:];
    -[NSObject retain];
    -[NSObject release];
    -[NSObject autorelease];
    -[NSObject retainCount];
    -[NSObject zone];
    -[NSObject hash];
    -[NSObject superclass];
    -[NSObject description];

    @optional

    /* optional instance methods */
    -[NSObject debugDescription];

    @end

    @protocol UIApplicationDelegate <NSObject>

    @required

    @property (T@"UIWindow",&,N) window;

    @optional

    /* optional instance methods */
    -[UIApplicationDelegate applicationDidFinishLaunching:];
    -[UIApplicationDelegate application:willFinishLaunchingWithOptions:];
    -[UIApplicationDelegate application:didFinishLaunchingWithOptions:];
    -[UIApplicationDelegate applicationDidBecomeActive:];
    -[UIApplicationDelegate applicationWillResignActive:];
    -[UIApplicationDelegate application:handleOpenURL:];
    -[UIApplicationDelegate application:openURL:sourceApplication:annotation:];
    -[UIApplicationDelegate application:openURL:options:];
    -[UIApplicationDelegate applicationDidReceiveMemoryWarning:];
    -[UIApplicationDelegate applicationWillTerminate:];
    -[UIApplicationDelegate applicationSignificantTimeChange:];
    -[UIApplicationDelegate application:willChangeStatusBarOrientation:duration:];
    -[UIApplicationDelegate application:didChangeStatusBarOrientation:];
    -[UIApplicationDelegate application:willChangeStatusBarFrame:];
    -[UIApplicationDelegate application:didChangeStatusBarFrame:];
    -[UIApplicationDelegate application:didRegisterUserNotificationSettings:];
    -[UIApplicationDelegate application:didRegisterForRemoteNotificationsWithDeviceToken:];
    -[UIApplicationDelegate application:didFailToRegisterForRemoteNotificationsWithError:];
    -[UIApplicationDelegate application:didReceiveRemoteNotification:];
    -[UIApplicationDelegate application:didReceiveLocalNotification:];
    -[UIApplicationDelegate application:handleActionWithIdentifier:forLocalNotification:completionHandler:];
    -[UIApplicationDelegate application:handleActionWithIdentifier:forRemoteNotification:withResponseInfo:completionHandler:];
    -[UIApplicationDelegate application:handleActionWithIdentifier:forRemoteNotification:completionHandler:];
    -[UIApplicationDelegate application:handleActionWithIdentifier:forLocalNotification:withResponseInfo:completionHandler:];
    -[UIApplicationDelegate application:didReceiveRemoteNotification:fetchCompletionHandler:];
    -[UIApplicationDelegate application:performFetchWithCompletionHandler:];
    -[UIApplicationDelegate application:performActionForShortcutItem:completionHandler:];
    -[UIApplicationDelegate application:handleEventsForBackgroundURLSession:completionHandler:];
    -[UIApplicationDelegate application:handleWatchKitExtensionRequest:reply:];
    -[UIApplicationDelegate applicationShouldRequestHealthAuthorization:];
    -[UIApplicationDelegate applicationDidEnterBackground:];
    -[UIApplicationDelegate applicationWillEnterForeground:];
    -[UIApplicationDelegate applicationProtectedDataWillBecomeUnavailable:];
    -[UIApplicationDelegate applicationProtectedDataDidBecomeAvailable:];
    -[UIApplicationDelegate application:supportedInterfaceOrientationsForWindow:];
    -[UIApplicationDelegate application:shouldAllowExtensionPointIdentifier:];
    -[UIApplicationDelegate application:viewControllerWithRestorationIdentifierPath:coder:];
    -[UIApplicationDelegate application:shouldSaveApplicationState:];
    -[UIApplicationDelegate application:shouldRestoreApplicationState:];
    -[UIApplicationDelegate application:willEncodeRestorableStateWithCoder:];
    -[UIApplicationDelegate application:didDecodeRestorableStateWithCoder:];
    -[UIApplicationDelegate application:willContinueUserActivityWithType:];
    -[UIApplicationDelegate application:continueUserActivity:restorationHandler:];
    -[UIApplicationDelegate application:didFailToContinueUserActivityWithType:error:];
    -[UIApplicationDelegate application:didUpdateUserActivity:];
    -[UIApplicationDelegate application:userDidAcceptCloudKitShareWithMetadata:];
    -[UIApplicationDelegate window];
    -[UIApplicationDelegate setWindow:];

    @end

    @protocol __ARCLiteKeyedSubscripting__

    @required

    /* required instance methods */
    -[__ARCLiteKeyedSubscripting__ objectForKeyedSubscript:];
    -[__ARCLiteKeyedSubscripting__ setObject:forKeyedSubscript:];

    @optional

    @end

    @interface AppDelegate : UIResponder <UIApplicationDelegate> {
        /* instance variables */
        @"UIWindow" _window;
    }

    @property (T@"UIWindow",&,N,V_window) window;
    @property (TQ,R) hash;
    @property (T#,R) superclass;
    @property (T@"NSString",R,C) description;
    @property (T@"NSString",R,C) debugDescription;

    /* instance methods */
    -[AppDelegate application:didFinishLaunchingWithOptions:];
    -[AppDelegate applicationWillResignActive:];
    -[AppDelegate applicationDidEnterBackground:];
    -[AppDelegate applicationWillEnterForeground:];
    -[AppDelegate applicationDidBecomeActive:];
    -[AppDelegate applicationWillTerminate:];
    -[AppDelegate window];
    -[AppDelegate setWindow:];

    @end

    @interface ViewController : UIViewController {
        /* instance variables */
        @"UILabel" _theLabel;
        @"UILabel" _Hint;
        @"UITextField" _theTextField;
        @"UIButton" _bVerify;
    }

    @property (T@"UILabel",W,N,V_theLabel) theLabel;
    @property (T@"UILabel",W,N,V_Hint) Hint;
    @property (T@"UITextField",W,N,V_theTextField) theTextField;
    @property (T@"UIButton",W,N,V_bVerify) bVerify;

    /* instance methods */
    -[ViewController viewDidLoad];
    -[ViewController buttonClick:];
    -[ViewController didReceiveMemoryWarning];
    -[ViewController theLabel];
    -[ViewController setTheLabel:];
    -[ViewController Hint];
    -[ViewController setHint:];
    -[ViewController theTextField];
    -[ViewController setTheTextField:];
    -[ViewController bVerify];
    -[ViewController setBVerify:];

    @end
    ```

## Extracting Swift Class Information

IPSW can output the available Swift symbols with `ipsw swift-dump`. By default, the location of the identified structures and symbols is not printed, but this can be enabled by using the `-V` flag:

```bash
$ ipsw swift-dump --arch arm64 ./MASTestApp -V

Swift TOC
--------
  __swift5_builtin  = 0
  __swift5_types(2) = 3
  __swift5_protos   = 0
  __swift5_proto    = 2

TYPES
-----

// 0x10000a760
struct MASTestApp.ContentView { // accessor 0x1000081e4
    /* 0x10000b064 */ var _displayText: _$s7SwiftUI5StateVMn _$sSS
}

// 0x10000a7a4
struct MASTestApp.MASTestAppApp {} // accessor 0x10000a200

// 0x10000a7f0
class MASTestApp.ResourceBundleClass { // accessor 0x10000a2c4
  /* methods */
    /* 0x10000a824 */ // <stripped> static func init
}
...

```

??? "Full command output"

    ```bash
    $ ipsw swift-dump --arch arm64 ./MASTestApp -V

    Swift TOC
    --------
    __swift5_builtin  = 0
    __swift5_types(2) = 3
    __swift5_protos   = 0
    __swift5_proto    = 2

    TYPES
    -----

    // 0x10000a760
    struct MASTestApp.ContentView { // accessor 0x1000081e4
        /* 0x10000b064 */ var _displayText: _$s7SwiftUI5StateVMn _$sSS
    }

    // 0x10000a7a4
    struct MASTestApp.MASTestAppApp {} // accessor 0x10000a200

    // 0x10000a7f0
    class MASTestApp.ResourceBundleClass { // accessor 0x10000a2c4
    /* methods */
        /* 0x10000a824 */ // <stripped> static func init
    }

    PROTOCOL CONFORMANCES
    ---------------------

    // 0x10000a668
    protocol conformance MASTestApp.ContentView : _$s7SwiftUI4ViewMp {
    /* resilient witnesses */
        /* 0x10000a83d */ _$s7SwiftUI4ViewP4BodyAC_AaBTn
        /* 0x10000a845 */ _$s4Body7SwiftUI4ViewPTl
        /* 0x100009924 */ _$s7SwiftUI4ViewP05_makeC04view6inputsAA01_C7OutputsVAA11_GraphValueVyxG_AA01_C6InputsVtFZTq
        /* 0x100009928 */ _$s7SwiftUI4ViewP05_makeC4List4view6inputsAA01_cE7OutputsVAA11_GraphValueVyxG_AA01_cE6InputsVtFZTq
        /* 0x10000992c */ _$s7SwiftUI4ViewP14_viewListCount6inputsSiSgAA01_ceF6InputsV_tFZTq
        /* 0x100009944 */ _$s7SwiftUI4ViewP4body4BodyQzvgTq
    }

    // 0x10000a6fc
    protocol conformance MASTestApp.MASTestAppApp : _$s7SwiftUI3AppMp {
    /* resilient witnesses */
        /* 0x10000afff */ _$s7SwiftUI3AppP4BodyAC_AA5SceneTn
        /* 0x10000b007 */ _$s4Body7SwiftUI3AppPTl
        /* 0x10000a0d4 */ _$s7SwiftUI3AppP4body4BodyQzvgTq
        /* 0x10000a184 */ _$s7SwiftUI3AppPxycfCTq
    }

    ASSOCIATED TYPES
    ---------------------

    // 0x10000b088
    extension MASTestApp.ContentView: _$s7SwiftUI4ViewP {
        /* 0x10000b03f */ typealias Body = _$s7SwiftUI15ModifiedContentVMn _$s7SwiftUI6VStackVMn _$s7SwiftUI9TupleViewVMn _$syAA -> _$s7SwiftUI6HStackVMn _$syAC -> _$s7SwiftUI4TextVMn _$s_ _$s7SwiftUI6SpacerVMn _$sAAyAAyAA -> _$s7SwiftUI6ButtonVMn _$syAAyAAyAAyAE _$s7SwiftUI14_PaddingLayoutVMn _$sGAHG _$s7SwiftUI30_EnvironmentKeyWritingModifierVMn _$s7SwiftUI4FontVMn _$sSgGGG -> _$s7SwiftUI24_BackgroundStyleModifierVMn _$s7SwiftUI14LinearGradientVMn _$sGG -> _$s7SwiftUI11_ClipEffectVMn _$s7SwiftUI16RoundedRectangleVMn _$sGGAHGtGGAHG_AAyAAyAAyAA -> _$s7SwiftUI10ScrollViewVMn _$syAAyAAyAE _$s7SwiftUI16_FlexFrameLayoutVMn _$sGAHGGA2_GAQ -> _$s7SwiftUI5ColorVMn _$sGGAWGAHGtGGAH
    }

    // 0x10000b0a0
    extension MASTestApp.MASTestAppApp: _$s7SwiftUI3AppP {
        /* 0x10000b044 */ typealias Body = _$s7SwiftUI11WindowGroupVMn MASTestApp.ContentView
    }

    ```
