---
title: Retrieving PrivacyInfo.xcprivacy Files
platform: ios
---

iOS apps can include [privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files) that provides information about the app's privacy practices as well as its components (e.g. Frameworks, Plugins, etc.). These files are typically named `PrivacyInfo.xcprivacy` and are used to declare the app's data collection practices, including any third-party libraries or frameworks that may collect user data.

To retrieve these files, you can use the following command in your terminal:

```sh
find . -name "PrivacyInfo.xcprivacy"
```

For example, assuming you have an iOS app named `TikTok.ipa`, and you've extracted it using @MASTG-TECH-0054, you can run the following commands from the `Payload/` folder to find all `PrivacyInfo.xcprivacy` files within the app bundle (truncated and reordered for readability):

```sh
find . -name "PrivacyInfo.xcprivacy"

./TikTok.app/PrivacyInfo.xcprivacy
./TikTok.app/HeimdallrPrivacyInfo.bundle/PrivacyInfo.xcprivacy
./TikTok.app/FirebaseCore_Privacy.bundle/PrivacyInfo.xcprivacy
./TikTok.app/BDMemoryMatrix.bundle/PrivacyInfo.xcprivacy
./TikTok.app/LottiePrivacyInfo.bundle/PrivacyInfo.xcprivacy
...
./TikTok.app/PlugIns/TikTokIntentExtension.appex/PrivacyInfo.xcprivacy
./TikTok.app/PlugIns/TikTokMessageExtension.appex/PrivacyInfo.xcprivacy
./TikTok.app/PlugIns/TikTokMessageExtension.appex/BDALog.bundle/PrivacyInfo.xcprivacy
./TikTok.app/PlugIns/AwemeWidgetExtension.appex/PrivacyInfo.xcprivacy
./TikTok.app/PlugIns/AwemeWidgetExtension.appex/BDALog.bundle/PrivacyInfo.xcprivacy
...
./TikTok.app/Extensions/TikTokBackgroundAssetExtension.appex/PrivacyInfo.xcprivacy
...
./TikTok.app/Frameworks/OMSDK_Bytedance1.framework/PrivacyInfo.xcprivacy
./TikTok.app/Frameworks/SpotifyLogin.framework/PrivacyInfo.xcprivacy
...
```

This output shows how TikTok has multiple `PrivacyInfo.xcprivacy` files, including one for the main app (`./TikTok.app/PrivacyInfo.xcprivacy`) and several others for its .bundles, PlugIns, Extensions and Frameworks (and any other nested .bundles).

Let's take a look at the main privacy manifest, `./TikTok.app/PrivacyInfo.xcprivacy` (truncated for readability):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>NSPrivacyAccessedAPITypes</key>
        <array>
                <dict>
                        <key>NSPrivacyAccessedAPIType</key>
                        <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
                        <key>NSPrivacyAccessedAPITypeReasons</key>
                        <array>
                                <string>CA92.1</string>
                                <string>1C8F.1</string>
                                ...
        </array>
        <key>NSPrivacyCollectedDataTypes</key>
        <array>
                <dict>
                        <key>NSPrivacyCollectedDataType</key>
                        <string>NSPrivacyCollectedDataTypeName</string>
                        <key>NSPrivacyCollectedDataTypeLinked</key>
                        <true/>
                        <key>NSPrivacyCollectedDataTypePurposes</key>
                        <array>
                                <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
                                <string>NSPrivacyCollectedDataTypePurposeOther</string>
                        </array>
                        <key>NSPrivacyCollectedDataTypeTracking</key>
                        <false/>
                </dict>
                ...
        </array>
        <key>NSPrivacyTracking</key>
        <true/>
        <key>NSPrivacyTrackingDomains</key>
        <array>
                <string>da-an-v3.tiktokv.com</string>
                <string>da-an-v3-va.tiktokv.com</string>
                ...
        </array>
</dict>
</plist>
```

See @MASTG-TECH-0138 for converting this file to JSON and @MASTG-TECH-0137 for more information on analyzing the contents of `PrivacyInfo.xcprivacy` files.
