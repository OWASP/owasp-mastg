---
title: IPSW
platform: ios
source: https://github.com/blacktop/ipsw
host: [windows, linux, macOS]
---

IPSW calls itself an "iOS/macOS Research Swiss Army Knife". In general, IPSW allows you to obtain iOS specific files (IPSW, OTA, ...) and also statically analyze them. For application analysis, the most interesting features are the Objective-C and Swift class-dumps. Other features are available (kernelcache parser, device-tree parser, disassembler, etc) but are only useful if you're analyzing the security of the OS itself.

## Extracting Objective-C Class Information

IPSW can extract Objective-C class information from a MachO binary. The desired architecture can be specified using `--arch` in case of a universal MachO file:

```bash
ipsw class-dump --arch arm64 UnCrackable\ Level\ 1

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
    ipsw class-dump --arch arm64 UnCrackable\ Level\ 1

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
ipsw swift-dump --arch arm64 TelegramCoreFramework -V .
Swift TOC
--------
  __swift5_builtin  = 167
  __swift5_types(2) = 1159
  __swift5_protos   = 14
  __swift5_proto    = 1170

TYPES
-----

// 0x5404f4
struct TelegramApi.Api {} // accessor 0x14ff54

// 0x54051c
struct TelegramApi.Api.messages {} // accessor 0x14ff60

// 0x540544
enum TelegramApi.Api.messages.StickerSet { // accessor 0x150138
    /* 0x5ad214 */ case stickerSet: TelegramApi.Api.StickerSet set_Sa TelegramApi.Api.StickerPack _$sG5packsSa -> TelegramApi.Api.Document _$sG9documentst
}

// 0x540574
enum TelegramApi.Api.messages.ArchivedStickers { // accessor 0x150218
    /* 0x5ad230 */ case archivedStickers: (private) count_Sa TelegramApi.Api.StickerSetCovered _$sG4setst ->
}

// 0x5405a0
enum TelegramApi.Api.messages.InactiveChats { // accessor 0x150244
    /* 0x5ad24c */ case inactiveChats: _$sSa -> (private) _$sG5dates_Sa -> TelegramApi.Api.Chat _$sG5chatsSa -> TelegramApi.Api.User _$sG5userst
}

// 0x5405d8
enum TelegramApi.Api.messages.SentEncryptedMessage { // accessor 0x15033c
    /* 0x5ad268 */ case sentEncryptedMessage: (private) date_t
    /* 0x5ad274 */ case sentEncryptedFile: (private) date_ TelegramApi.Api.EncryptedFile filet
}

...

```

## Converting plist Files

IPSW can convert a binary plist or XML plist to JSON:

```bash
ipsw plist ./Info.plist
{
  "BuildMachineOSBuild": "15G1212",
  "CFBundleDevelopmentRegion": "en",
  "CFBundleDisplayName": "UnCrackable1",
  "CFBundleExecutable": "UnCrackable Level 1",
  "CFBundleIcons": {
    ...
```

??? "Full command output"

    ```bash
    ipsw plist ./Info.plist

    {
    "BuildMachineOSBuild": "15G1212",
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "UnCrackable1",
    "CFBundleExecutable": "UnCrackable Level 1",
    "CFBundleIcons": {
        "CFBundlePrimaryIcon": {
        "CFBundleIconFiles": [
            "AppIcon-120x20",
            "AppIcon-129x29",
            "AppIcon-140x40",
            "AppIcon-157x57",
            "AppIcon-160x60"
        ]
        }
    },
    "CFBundleIcons~ipad": {
        "CFBundlePrimaryIcon": {
        "CFBundleIconFiles": [
            "AppIcon-120x20",
            "AppIcon-129x29",
            "AppIcon-140x40",
            "AppIcon-157x57",
            "AppIcon-160x60",
            "AppIcon-150x50",
            "AppIcon-172x72",
            "AppIcon-176x76",
            "AppIcon-183.5x83.5"
        ]
        }
    },
    "CFBundleIdentifier": "sg.vp.UnCrackable1",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "UnCrackable Level 1",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "1.0",
    "CFBundleSupportedPlatforms": [
        "iPhoneOS"
    ],
    "CFBundleVersion": "1",
    "DTCompiler": "com.apple.compilers.llvm.clang.1_0",
    "DTPlatformBuild": "14C89",
    "DTPlatformName": "iphoneos",
    "DTPlatformVersion": "10.2",
    "DTSDKBuild": "14C89",
    "DTSDKName": "iphoneos10.2",
    "DTXcode": "0821",
    "DTXcodeBuild": "8C1002",
    "LSRequiresIPhoneOS": true,
    "MinimumOSVersion": "8.0",
    "UIDeviceFamily": [
        1,
        2
    ],
    "UILaunchStoryboardName": "LaunchScreen",
    "UIMainStoryboardFile": "Main",
    "UIRequiredDeviceCapabilities": [
        "armv7"
    ],
    "UISupportedInterfaceOrientations": [
        "UIInterfaceOrientationPortrait",
        "UIInterfaceOrientationLandscapeLeft",
        "UIInterfaceOrientationLandscapeRight"
    ],
    "UISupportedInterfaceOrientations~ipad": [
        "UIInterfaceOrientationPortrait",
        "UIInterfaceOrientationPortraitUpsideDown",
        "UIInterfaceOrientationLandscapeLeft",
        "UIInterfaceOrientationLandscapeRight"
    ]
    }
    ```