---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: Testing App Extensions
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

The static analysis will take care of:

- Verifying if the app contains app extensions
- Determining the supported data types
- Checking data sharing with the containing app
- Verifying if the app restricts the use of app extensions

### Verifying if the App Contains App Extensions

If you have the original source code you can search for all occurrences of `NSExtensionPointIdentifier` with Xcode (cmd+shift+f) or take a look into "Build Phases / Embed App extensions":

<img src="Images/Chapters/0x06h/xcode_embed_app_extensions.png" width="100%" />

There you can find the names of all embedded app extensions followed by `.appex`, now you can navigate to the individual app extensions in the project.

If not having the original source code:

Grep for `NSExtensionPointIdentifier` among all files inside the app bundle (IPA or installed app):

```bash
$ grep -nr NSExtensionPointIdentifier Payload/Telegram\ X.app/
Binary file Payload/Telegram X.app//PlugIns/SiriIntents.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/Share.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/NotificationContent.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/Widget.appex/Info.plist matches
Binary file Payload/Telegram X.app//Watch/Watch.app/PlugIns/Watch Extension.appex/Info.plist matches
```

You can also access per SSH, find the app bundle and list all inside PlugIns (they are placed there by default) or do it with objection:

```bash
ph.telegra.Telegraph on (iPhone: 11.1.2) [usb] # cd PlugIns
    /var/containers/Bundle/Application/15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35/
    Telegram X.app/PlugIns

ph.telegra.Telegraph on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    Read    Write     Name
------------  -------  ------------------  ------  -------   -------------------------
Directory         493  None                True    False     NotificationContent.appex
Directory         493  None                True    False     Widget.appex
Directory         493  None                True    False     Share.appex
Directory         493  None                True    False     SiriIntents.appex
```

We can see now the same four app extensions that we saw in Xcode before.

### Determining the Supported Data Types

This is important for data being shared with host apps (e.g. via Share or Action Extensions). When the user selects some data type in a host app and it matches the data types define here, the host app will offer the extension. It is worth noticing the difference between this and data sharing via `UIActivity` where we had to define the document types, also using UTIs. An app does not need to have an extension for that. It is possible to share data using only `UIActivity`.

Inspect the app extension's `Info.plist` file and search for `NSExtensionActivationRule`. That key specifies the data being supported as well as e.g. maximum of items supported. For example:

```xml
<key>NSExtensionAttributes</key>
    <dict>
        <key>NSExtensionActivationRule</key>
        <dict>
            <key>NSExtensionActivationSupportsImageWithMaxCount</key>
            <integer>10</integer>
            <key>NSExtensionActivationSupportsMovieWithMaxCount</key>
            <integer>1</integer>
            <key>NSExtensionActivationSupportsWebURLWithMaxCount</key>
            <integer>1</integer>
        </dict>
    </dict>
```

Only the data types present here and not having `0` as `MaxCount` will be supported. However, more complex filtering is possible by using a so-called predicate string that will evaluate the UTIs given. Please refer to the [Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html#//apple_ref/doc/uid/TP40014214-CH21-SW8 "Declaring Supported Data Types for a Share or Action Extension") for more detailed information about this.

### Checking Data Sharing with the Containing App

Remember that app extensions and their containing apps do not have direct access to each other's containers. However, data sharing can be enabled. This is done via ["App Groups"](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html#//apple_ref/doc/uid/TP40011195-CH4-SW19 "Adding an App to an App Group") and the [`NSUserDefaults`](https://developer.apple.com/documentation/foundation/nsuserdefaults "NSUserDefaults") API. See this figure from [Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html#//apple_ref/doc/uid/TP40014214-CH21-SW11 "An app extension's container is distinct from its containing app's container"):

<img src="Images/Chapters/0x06h/app_extensions_container_restrictions.png" width="400px" />

As also mentioned in the guide, the app must set up a shared container if the app extension uses the `NSURLSession` class to perform a background upload or download, so that both the extension and its containing app can access the transferred data.

### Verifying if the App Restricts the Use of App Extensions

It is possible to reject a specific type of app extension by using the following method:

- [`application:shouldAllowExtensionPointIdentifier:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623122-application?language=objc "UIApplicationDelegate application:shouldAllowExtensionPointIdentifier:")

However, it is currently only possible for "custom keyboard" app extensions (and should be verified when testing apps handling sensitive data via the keyboard like e.g. banking apps).

## Dynamic Analysis

For the dynamic analysis we can do the following to gain knowledge without having the source code:

- Inspecting the items being shared
- Identifying the app extensions involved

### Inspecting the Items Being Shared

For this we should hook `NSExtensionContext - inputItems` in the data originating app.

Following the previous example of Telegram we will now use the "Share" button on a text file (that was received from a chat) to create a note in the Notes app with it:

<img src="Images/Chapters/0x06h/telegram_share_extension.png" width="400px" />

If we run a trace, we'd see the following output:

```bash
(0x1c06bb420) NSExtensionContext - inputItems
0x18284355c Foundation!-[NSExtension _itemProviderForPayload:extensionContext:]
0x1828447a4 Foundation!-[NSExtension _loadItemForPayload:contextIdentifier:completionHandler:]
0x182973224 Foundation!__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S3__
0x182971968 Foundation!-[NSXPCConnection _decodeAndInvokeMessageWithEvent:flags:]
0x182748830 Foundation!message_handler
0x181ac27d0 libxpc.dylib!_xpc_connection_call_event_handler
0x181ac0168 libxpc.dylib!_xpc_connection_mach_event
...
RET: (
"<NSExtensionItem: 0x1c420a540> - userInfo:
{
    NSExtensionItemAttachmentsKey =     (
    "<NSItemProvider: 0x1c46b30e0> {types = (\n \"public.plain-text\",\n \"public.file-url\"\n)}"
    );
}"
)
```

Here we can observe that:

- This occurred under-the-hood via XPC, concretely it is implemented via a `NSXPCConnection` that uses the `libxpc.dylib` Framework.
- The UTIs included in the `NSItemProvider` are `public.plain-text` and `public.file-url`, the latter being included in `NSExtensionActivationRule` from the [`Info.plist` of the "Share Extension" of Telegram](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/Telegram/Share/Info.plist "Info.plist of the \'Share Extension\' of Telegram").

### Identifying the App Extensions Involved

You can also find out which app extension is taking care of your the requests and responses by hooking `NSExtension - _plugIn`:

We run the same example again:

```bash
(0x1c0370200) NSExtension - _plugIn
RET: <PKPlugin: 0x1163637f0 ph.telegra.Telegraph.Share(5.3) 5B6DE177-F09B-47DA-90CD-34D73121C785
1(2) /private/var/containers/Bundle/Application/15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35
/Telegram X.app/PlugIns/Share.appex>

(0x1c0372300)  -[NSExtension _plugIn]
RET: <PKPlugin: 0x10bff7910 com.apple.mobilenotes.SharingExtension(1.5) 73E4F137-5184-4459-A70A-83
F90A1414DC 1(2) /private/var/containers/Bundle/Application/5E267B56-F104-41D0-835B-F1DAB9AE076D
/MobileNotes.app/PlugIns/com.apple.mobilenotes.SharingExtension.appex>
```

As you can see there are two app extensions involved:

- `Share.appex` is sending the text file (`public.plain-text` and `public.file-url`).
- `com.apple.mobilenotes.SharingExtension.appex` which is receiving and will process the text file.

If you want to learn more about what's happening under-the-hood in terms of XPC, we recommend to take a look at the internal calls from "libxpc.dylib". For example you can use [`frida-trace`](https://www.frida.re/docs/frida-trace/ "frida-trace") and then dig deeper into the methods that you find more interesting by extending the automatically generated stubs.
