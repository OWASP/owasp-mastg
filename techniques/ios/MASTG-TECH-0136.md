---
title: Retrieving PrivacyInfo.xcprivacy Files
platform: ios
---

iOS apps can include [privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files) that provides information about the app's privacy practices as well as its components (e.g. Frameworks, Plugins, etc.). These files are typically named `PrivacyInfo.xcprivacy` and are used to declare the app's data collection practices, including any third-party libraries or frameworks that may collect user data.

To retrieve these files, you can use the following command in your terminal:

```sh
find . -name "PrivacyInfo.xcprivacy"
```

For example, assuming you have an iOS social media app named `SocialApp.ipa`, and you've extracted it using @MASTG-TECH-0054, you can run the following commands from the `Payload/` folder to find all `PrivacyInfo.xcprivacy` files within the app bundle (truncated and reordered for readability):

```sh
find . -name "PrivacyInfo.xcprivacy"

./SocialApp.app/PrivacyInfo.xcprivacy
./SocialApp.app/FirebaseCore_Privacy.bundle/PrivacyInfo.xcprivacy
./SocialApp.app/LetterPrivacyInfo.bundle/PrivacyInfo.xcprivacy
./SocialApp.app/CoreMain.bundle/PrivacyInfo.xcprivacy
...
./SocialApp.app/PlugIns/WidgetExtension.appex/PrivacyInfo.xcprivacy
./SocialApp.app/PlugIns/WidgetExtension.appex/Deep_Privacy.bundle/PrivacyInfo.xcprivacy
...
./SocialApp.app/Extensions/SocialAppAssetExtension.appex/PrivacyInfo.xcprivacy
...
./SocialApp.app/Frameworks/OXSDK_1.framework/PrivacyInfo.xcprivacy
./SocialApp.app/Frameworks/SpotifyLogin.framework/PrivacyInfo.xcprivacy
...
```

This output shows how SocialApp has multiple `PrivacyInfo.xcprivacy` files, including one for the main app (`./SocialApp.app/PrivacyInfo.xcprivacy`) and several others for its .bundles, PlugIns, Extensions and Frameworks (and any other nested .bundles).

Let's take a look at the main privacy manifest, `./SocialApp.app/PrivacyInfo.xcprivacy` (truncated for readability):

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
                <string>trk-v2.socialapp.com</string>
                <string>trk-v2.socialapp.us</string>
                ...
        </array>
</dict>
</plist>
```

See @MASTG-TECH-0138 for converting this file to JSON and @MASTG-TECH-0137 for more information on analyzing the contents of `PrivacyInfo.xcprivacy` files.
