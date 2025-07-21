---
masvs_category: MASVS-PLATFORM
platform: ios
title: App Permissions
---

In contrast to Android, where each app runs on its own user ID, iOS makes all third-party apps run under the non-privileged `mobile` user. Each app has a unique home directory and is sandboxed, so that they cannot access protected system resources or files stored by the system or by other apps. These restrictions are implemented via sandbox policies (aka. _profiles_), which are enforced by the [Trusted BSD (MAC) Mandatory Access Control Framework](http://www.trustedbsd.org/mac.html "TrustedBSD Mandatory Access Control (MAC) Framework") via a kernel extension. iOS applies a generic sandbox profile to all third-party apps called _container_. Access to protected resources or data (some also known as [app capabilities](https://developer.apple.com/support/app-capabilities/ "Advanced App Capabilities")) is possible, but it's strictly controlled via special permissions known as _entitlements_.

Some permissions can be configured by the app's developers (e.g. Data Protection or Keychain Sharing) and will directly take effect after the installation. However, for others, the user will be explicitly asked the first time the app attempts to access a protected resource, [for example](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Data and resources protected by system authorization settings"):

- Bluetooth peripherals
- Calendar data
- Camera
- Contacts
- Health sharing
- Health updating
- HomeKit
- Location
- Microphone
- Motion
- Music and the media library
- Photos
- Reminders
- Siri
- Speech recognition
- the TV provider

Even though Apple urges to protect the privacy of the user and to be [very clear on how to ask permissions](https://developer.apple.com/design/human-interface-guidelines/privacy "Requesting Permission"), it can still be the case that an app requests too many of them for non-obvious reasons.

Verifying the use of some permissions such as Camera, Photos, Calendar Data, Motion, Contacts or Speech Recognition should be pretty straightforward as it should be obvious if the app requires them to fulfill its tasks. Let's consider the following examples regarding the Photos permission, which, if granted, gives the app access to all user photos in the "Camera Roll" (the iOS default system-wide location for storing photos):

- The typical QR Code scanning app obviously requires the camera to function but might be requesting the photos permission as well. If storage is explicitly required, and depending on the sensitivity of the pictures being taken, these apps might better opt to use the app sandbox storage to avoid other apps (having the photos permission) to access them. See the chapter ["Data Storage on iOS"](0x06d-Testing-Data-Storage.md) for more information regarding storage of sensitive data.
- Some apps require photo uploads (e.g. for profile pictures). Recent versions of iOS introduce new APIs such as [`UIImagePickerController`](https://developer.apple.com/documentation/uikit/uiimagepickercontroller "UIImagePickerController") (iOS 11+) and its modern [replacement](https://developer.apple.com/videos/play/wwdc2020/10652/ "replacement") [`PHPickerViewController`](https://developer.apple.com/documentation/photokit/phpickerviewcontroller "PHPickerViewController") (iOS 14+). These APIs run on a separate process from your app and by using them, the app gets read-only access exclusively to the images selected by the user instead of to the whole "Camera Roll". This is considered a best practice to avoid requesting unnecessary permissions.

Verifying other permissions like Bluetooth or Location require a deeper source code inspection. They may be required for the app to properly function but the data being handled by those tasks might not be properly protected.

When collecting or simply handling (e.g. caching) sensitive data, an app should provide proper mechanisms to give the user control over it, e.g. to be able to revoke access or to delete it. However, sensitive data might not only be stored or cached but also sent over the network. In both cases, it has to be ensured that the app properly follows the appropriate best practices, which in this case involve implementing proper data protection and transport security. More information on how to protect this kind of data can be found in the chapter "Network APIs".

As you can see, using app capabilities and permissions mostly involve handling personal data, therefore being a matter of protecting the user's privacy. See the articles ["Protecting the User's Privacy"](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy "Protecting the User\'s Privacy") and ["Accessing Protected Resources"](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc "Accessing Protected Resources") in Apple Developer Documentation for more details.

## Device Capabilities

Device capabilities are used by the App Store to ensure that only compatible devices are listed and therefore are allowed to download the app. They are specified in the `Info.plist` file of the app under the [`UIRequiredDeviceCapabilities`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/plist/info/UIRequiredDeviceCapabilities "UIRequiredDeviceCapabilities") key.

```xml
<key>UIRequiredDeviceCapabilities</key>
<array>
    <string>arm64</string>
</array>
```

> Typically you'll find the `arm64` capability, meaning that the app is compiled for the arm64 instruction set.

For example, an app might be completely dependent on NFC to work (e.g. a ["NFC Tag Reader"](https://itunes.apple.com/us/app/nfc-taginfo-by-nxp/id1246143596 "NFC TagInfo by NXP") app). According to the [archived iOS Device Compatibility Reference](https://developer.apple.com/library/archive/documentation/DeviceInformation/Reference/iOSDeviceCompatibility/DeviceCompatibilityMatrix/DeviceCompatibilityMatrix.html "iOS Device Compatibility Matrix"), NFC is only available starting on the iPhone 7 (and iOS 11). A developer might want to exclude all incompatible devices by setting the `nfc` device capability.

Regarding testing, you can consider `UIRequiredDeviceCapabilities` as a mere indication that the app is using some specific resources. Unlike the entitlements related to app capabilities, device capabilities do not confer any right or access to protected resources. Additional configuration steps might be required for that, which are very specific to each capability.

For example, if BLE is a core feature of the app, Apple's [Core Bluetooth Programming Guide](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothOverview/CoreBluetoothOverview.html#//apple_ref/doc/uid/TP40013257-CH2-SW1 "Core Bluetooth Overview") explains the different things to be considered:

- The `bluetooth-le` device capability can be set in order to _restrict_ non-BLE capable devices from downloading their app.
- App capabilities like `bluetooth-peripheral` or `bluetooth-central` (both `UIBackgroundModes`) should be added if [BLE background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html "Core Bluetooth Background Processing for iOS Apps") is required.

However, this is not yet enough for the app to get access to the Bluetooth peripheral, the `NSBluetoothPeripheralUsageDescription` key has to be included in the `Info.plist` file, meaning that the user has to actively give permission. See "Purpose Strings in the Info.plist File" below for more information.

## Entitlements

According to [Apple's iOS Security Guide](https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf "iOS Security Guide"):

> Entitlements are key value pairs that are signed in to an app and allow authentication beyond runtime factors, like UNIX user ID. Since entitlements are digitally signed, they can't be changed. Entitlements are used extensively by system apps and daemons to perform specific privileged operations that would otherwise require the process to run as root. This greatly reduces the potential for privilege escalation by a compromised system app or daemon.

Many entitlements can be set using the "Summary" tab of the Xcode target editor. Other entitlements require editing a target's entitlements property list file or are inherited from the iOS provisioning profile used to run the app.

[Entitlement Sources](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-SOURCES "Entitlement Sources"):

1. Entitlements embedded in a provisioning profile that is used to code sign the app, which are composed of:
   - Capabilities defined on the Xcode project's target Capabilities tab, and/or:
   - Enabled Services on the app's App ID which are configured on the Identifiers section of the Certificates, ID's and Profiles website.
   - Other entitlements that are injected by the profile generation service.
2. Entitlements from a code signing entitlements file.

[Entitlement Destinations](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-DESTINATIONS "Entitlement Destinations"):

1. The app's signature.
2. The app's embedded provisioning profile.

The [Apple Developer Documentation](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-APPENTITLEMENTS "Inspect the entitlements of a built app") also explains:

- During code signing, the entitlements corresponding to the app's enabled Capabilities/Services are transferred to the app's signature from the provisioning profile Xcode chose to sign the app.
- The provisioning profile is embedded into the app bundle during the build (`embedded.mobileprovision`).
- Entitlements from the "Code Signing Entitlements" section in Xcode's "Build Settings" tab are transferred to the app's signature.

For example, if you want to set the "Default Data Protection" capability, you would need to go to the **Capabilities** tab in Xcode and enable **Data Protection**. This is directly written by Xcode to the `<appname>.entitlements` file as the `com.apple.developer.default-data-protection` entitlement with default value `NSFileProtectionComplete`. In the IPA we might find this in the `embedded.mobileprovision` as:

```xml
<key>Entitlements</key>
<dict>
    ...
    <key>com.apple.developer.default-data-protection</key>
    <string>NSFileProtectionComplete</string>
</dict>
```

For other capabilities such as HealthKit, the user has to be asked for permission, therefore it is not enough to add the entitlements, special keys and strings have to be added to the `Info.plist` file of the app.

## Purpose Strings in the Info.plist File

[_Purpose strings_](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037322 "Provide a Purpose String") or_usage description strings_ are custom texts that are offered to users in the system's permission request alert when requesting permission to access protected data or resources.

<img src="Images/Chapters/0x06h/permission_request_alert.png" width="400px" />

If linking on or after iOS 10, developers are required to include purpose strings in their app's [`Info.plist`](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW5 "The Information Property List File") file. Otherwise, if the app attempts to access protected data or resources without having provided the corresponding purpose string, [the access will fail and the app might even crash](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc "Accessing Protected Resources").

For an overview of the different _purpose strings Info.plist keys_ available see Table 1-2 at the [Apple App Programming Guide for iOS](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Data and resources protected by system authorization settings"). Click on the provided links to see the full description of each key in the [CocoaKeys reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Cocoa Keys").

## Code Signing Entitlements File

Certain capabilities require a [code signing entitlements file](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-ENTITLEMENTSFILE "Code Signing Entitlements files") (`<appname>.entitlements`). It is automatically generated by Xcode but may be manually edited and/or extended by the developer as well.

Here is an example of entitlements file of the [open source app Telegram](https://github.com/peter-iakovlev/Telegram-iOS/blob/77ee5c4dabdd6eb5f1e2ff76219edf7e18b45c00/Telegram-iOS/Telegram-iOS-AppStoreLLC.entitlements#L23 "Telegram-iOS-AppStoreLLC.entitlements Line 23") including the [App Groups entitlement](https://developer.apple.com/documentation/foundation/com_apple_security_application-groups "App Groups entitlement") (`application-groups`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
...
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.ph.telegra.Telegraph</string>
    </array>
</dict>
...
</plist>
```

The entitlement outlined above does not require any additional permissions from the user. However, it is always a good practice to check all entitlements, as the app might overask the user in terms of permissions and thereby leak information.

As documented at [Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html#//apple_ref/doc/uid/TP40011195-CH4-SW19 "Adding an App to an App Group"), the App Groups entitlement is required to share information between different apps through IPC or a shared file container, which means that data can be shared on the device directly between the apps.
This entitlement is also required if an app extension requires to [share information with its containing app](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html "Sharing Data with Your Containing App").

Depending on the data to-be-shared it might be more appropriate to share it using another method such as through a backend where this data could be potentially verified, avoiding tampering by e.g. the user themselves.
