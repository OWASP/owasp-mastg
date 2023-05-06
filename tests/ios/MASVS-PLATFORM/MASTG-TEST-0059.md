---
masvs_v1_id:
- MSTG-STORAGE-9
masvs_v2_id:
- MASVS-PLATFORM-3
platform: ios
title: Testing Auto-Generated Screenshots for Sensitive Information
masvs_v1_levels:
- L2
---

## Overview

## Static Analysis

If you have the source code, search for the [`applicationDidEnterBackground`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622997-applicationdidenterbackground) method to determine whether the application sanitizes the screen before being backgrounded.

The following is a sample implementation using a default background image (`overlayImage.png`) whenever the application is backgrounded, overriding the current view:

Swift:

```swift
private var backgroundImage: UIImageView?

func applicationDidEnterBackground(_ application: UIApplication) {
    let myBanner = UIImageView(image: #imageLiteral(resourceName: "overlayImage"))
    myBanner.frame = UIScreen.main.bounds
    backgroundImage = myBanner
    window?.addSubview(myBanner)
}

func applicationWillEnterForeground(_ application: UIApplication) {
    backgroundImage?.removeFromSuperview()
}
```

Objective-C:

```objectivec
@property (UIImageView *)backgroundImage;

- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    self.backgroundImage.bounds = UIScreen.mainScreen.bounds;
    [self.window addSubview:myBanner];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    [self.backgroundImage removeFromSuperview];
}
```

This sets the background image to `overlayImage.png` whenever the application is backgrounded. It prevents sensitive data leaks because `overlayImage.png` will always override the current view.

## Dynamic Analysis

You can use a _visual approach_ to quickly validate this test case using any iOS device (jailbroken or not):

1. Navigate to an application screen that displays sensitive information, such as a username, an email address, or account details.
2. Background the application by hitting the **Home** button on your iOS device.
3. Verify that a default image is shown as the top view element instead of the view containing the sensitive information.

If required, you may also collect evidence by performing steps 1 to 3 on a jailbroken device or a non-jailbroken device after [repackaging the app with the Frida Gadget](../../../Document/0x06c-Reverse-Engineering-and-Tampering.md#dynamic-analysis-on-non-jailbroken-devices). After that, connect to the iOS device [per SSH](../../../Document/0x06b-Basic-Security-Testing.md#accessing-the-device-shell) or [by other means](0x06b-Basic-Security-Testing.md#host-device-data-transfer) and navigate to the Snapshots directory. The location may differ on each iOS version but it's usually inside the app's Library directory. On iOS 14.5:
    `/var/mobile/Containers/Data/Application/$APP_ID/Library/SplashBoard/Snapshots/sceneID:$APP_NAME-default/`

The screenshots inside that folder should not contain any sensitive information.
