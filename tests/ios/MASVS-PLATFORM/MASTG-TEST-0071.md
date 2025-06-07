---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: Testing UIActivity Sharing
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

### Sending Items

When testing `UIActivity` Sharing you should pay special attention to:

- the data (items) being shared,
- the custom activities,
- the excluded activity types.

Data sharing via `UIActivity` works by creating a `UIActivityViewController` and passing it the desired items (URLs, text, a picture) on [`init(activityItems: applicationActivities:)`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622019-init "UIActivityViewController init(activityItems:applicationActivities:)").

As we mentioned before, it is possible to exclude some of the sharing mechanisms via the controller's [`excludedActivityTypes` property](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622009-excludedactivitytypes "UIActivityViewController excludedActivityTypes"). It is highly recommended to do the tests using the latest versions of iOS as the number of activity types that can be excluded can increase. The developers have to be aware of this and **explicitly exclude** the ones that are not appropriate for the app data. Some activity types might not be even documented like "Create Watch Face".

If having the source code, you should take a look at the `UIActivityViewController`:

- Inspect the activities passed to the `init(activityItems:applicationActivities:)` method.
- Check if it defines custom activities (also being passed to the previous method).
- Verify the `excludedActivityTypes`, if any.

If you only have the compiled/installed app, try searching for the previous method and property, for example using @MASTG-TOOL-0129:

```bash
$ rabin2 -zq Telegram\ X.app/Telegram\ X | grep -i activityItems
0x1000df034 45 44 initWithActivityItems:applicationActivities:
```

### Receiving Items

When receiving items, you should check:

- if the app declares _custom document types_ by looking into Exported/Imported UTIs ("Info" tab of the Xcode project). The list of all system declared UTIs (Uniform Type Identifiers) can be found in the [archived Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/UTIRef/Articles/System-DeclaredUniformTypeIdentifiers.html#//apple_ref/doc/uid/TP40009259 "System-Declared Uniform Type Identifiers").
- if the app specifies any _document types that it can open_ by looking into Document Types ("Info" tab of the Xcode project). If present, they consist of name and one or more UTIs that represent the data type (e.g. "public.png" for PNG files). iOS uses this to determine if the app is eligible to open a given document (specifying Exported/Imported UTIs is not enough).
- if the app properly _verifies the received data_ by looking into the implementation of [`application:openURL:options:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application?language=objc "UIApplicationDelegate application:openURL:options:") (or its deprecated version [`UIApplicationDelegate application:openURL:sourceApplication:annotation:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application?language=objc "UIApplicationDelegate application:openURL:sourceApplication:annotation:")) in the app delegate.

If not having the source code you can still take a look into the `Info.plist` file and search for:

- `UTExportedTypeDeclarations`/`UTImportedTypeDeclarations` if the app declares exported/imported _custom document types_.
- `CFBundleDocumentTypes` to see if the app specifies any _document types that it can open_.

A very complete explanation about the use of these keys can be found [on Stackoverflow](https://stackoverflow.com/questions/21937978/what-are-utimportedtypedeclarations-and-utexportedtypedeclarations-used-for-on-i "What are UTImportedTypeDeclarations and UTExportedTypeDeclarations used for on iOS?").

Let's see a real-world example. We will take a File Manager app and take a look at these keys. We used @MASTG-TOOL-0038 here to read the `Info.plist` file.

```bash
objection --gadget SomeFileManager run ios plist cat Info.plist
```

> Note that this is the same as if we would retrieve the IPA from the phone or accessed via e.g. SSH and navigated to the corresponding folder in the IPA / app sandbox. However, with objection we are just _one command away_ from our goal and this can be still considered static analysis.

The first thing we noticed is that app does not declare any imported custom document types but we could find a couple of exported ones:

```xml
UTExportedTypeDeclarations =     (
            {
        UTTypeConformsTo =             (
            "public.data"
        );
        UTTypeDescription = "SomeFileManager Files";
        UTTypeIdentifier = "com.some.filemanager.custom";
        UTTypeTagSpecification =             {
            "public.filename-extension" =                 (
                ipa,
                deb,
                zip,
                rar,
                tar,
                gz,
                ...
                key,
                pem,
                p12,
                cer
            );
        };
    }
);
```

The app also declares the document types it opens as we can find the key `CFBundleDocumentTypes`:

```xml
CFBundleDocumentTypes =     (
        {
        ...
        CFBundleTypeName = "SomeFileManager Files";
        LSItemContentTypes =             (
            "public.content",
            "public.data",
            "public.archive",
            "public.item",
            "public.database",
            "public.calendar-event",
            ...
        );
    }
);
```

We can see that this File Manager will try to open anything that conforms to any of the UTIs listed in `LSItemContentTypes` and it's ready to open files with the extensions listed in `UTTypeTagSpecification/"public.filename-extension"`. Please take a note of this because it will be useful if you want to search for vulnerabilities when dealing with the different types of files when performing dynamic analysis.

## Dynamic Analysis

### Sending Items

There are three main things you can easily inspect by performing dynamic instrumentation:

- The `activityItems`: an array of the items being shared. They might be of different types, e.g. one string and one picture to be shared via a messaging app.
- The `applicationActivities`: an array of `UIActivity` objects representing the app's custom services.
- The `excludedActivityTypes`: an array of the Activity Types that are not supported, e.g. `postToFacebook`.

To achieve this you can do two things:

- Hook the method we have seen in the static analysis ([`init(activityItems: applicationActivities:)`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622019-init "UIActivityViewController init(activityItems:applicationActivities:)")) to get the `activityItems` and `applicationActivities`.
- Find out the excluded activities by hooking [`excludedActivityTypes` property](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622009-excludedactivitytypes "UIActivityViewController excludedActivityTypes").

Let's see an example using Telegram to share a picture and a text file. First prepare the hooks, we will use the Frida REPL and write a script for this:

```javascript
Interceptor.attach(
ObjC.classes.
    UIActivityViewController['- initWithActivityItems:applicationActivities:'].implementation, {
  onEnter: function (args) {

    printHeader(args)

    this.initWithActivityItems = ObjC.Object(args[2]);
    this.applicationActivities = ObjC.Object(args[3]);

    console.log("initWithActivityItems: " + this.initWithActivityItems);
    console.log("applicationActivities: " + this.applicationActivities);

  },
  onLeave: function (retval) {
    printRet(retval);
  }
});

Interceptor.attach(
ObjC.classes.UIActivityViewController['- excludedActivityTypes'].implementation, {
  onEnter: function (args) {
    printHeader(args)
  },
  onLeave: function (retval) {
    printRet(retval);
  }
});

function printHeader(args) {
  console.log(Memory.readUtf8String(args[1]) + " @ " + args[1])
};

function printRet(retval) {
  console.log('RET @ ' + retval + ': ' );
  try {
    console.log(new ObjC.Object(retval).toString());
  } catch (e) {
    console.log(retval.toString());
  }
};
```

You can store this as a JavaScript file, e.g. `inspect_send_activity_data.js` and load it like this:

```bash
frida -U Telegram -l inspect_send_activity_data.js
```

Now observe the output when you first share a picture:

```javascript
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<UIImage: 0x1c4aa0b40> size {571, 264} orientation 0 scale 1.000000"
)
applicationActivities: nil
RET @ 0x13cb2b800:
<UIActivityViewController: 0x13cb2b800>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x0:
nil
```

and then a text file:

```javascript
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<QLActivityItemProvider: 0x1c4a30140>",
    "<UIPrintInfo: 0x1c0699a50>"
)
applicationActivities: (
)
RET @ 0x13c4bdc00:
<_UIDICActivityViewController: 0x13c4bdc00>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x1c001b1d0:
(
    "com.apple.UIKit.activity.MarkupAsPDF"
)
```

You can see that:

- For the picture, the activity item is a `UIImage` and there are no excluded activities.
- For the text file there are two different activity items and `com.apple.UIKit.activity. MarkupAsPDF` is excluded.

In the previous example, there were no custom `applicationActivities` and only one excluded activity. However, to better illustrate what you can expect from other apps we have shared a picture using another app, here you can see a bunch of application activities and excluded activities (output was edited to hide the name of the originating app):

```javascript
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<SomeActivityItemProvider: 0x1c04bd580>"
)
applicationActivities: (
    "<SomeActionItemActivityAdapter: 0x141de83b0>",
    "<SomeActionItemActivityAdapter: 0x147971cf0>",
    "<SomeOpenInSafariActivity: 0x1479f0030>",
    "<SomeOpenInChromeActivity: 0x1c0c8a500>"
)
RET @ 0x142138a00:
<SomeActivityViewController: 0x142138a00>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x14797c3e0:
(
    "com.apple.UIKit.activity.Print",
    "com.apple.UIKit.activity.AssignToContact",
    "com.apple.UIKit.activity.SaveToCameraRoll",
    "com.apple.UIKit.activity.CopyToPasteboard",
)
```

### Receiving Items

After performing the static analysis you would know the _document types that the app can open_ and _if it declares any custom document types_ and (part of) the methods involved. You can use this now to test the receiving part:

- _Share_ a file with the app from another app or send it via AirDrop or e-mail. Choose the file so that it will trigger the "Open with..." dialogue (that is, there is no default app that will open the file, a PDF for example).
- Hook `application:openURL:options:` and any other methods that were identified in a previous static analysis.
- Observe the app behavior.
- In addition, you could send specific malformed files and/or use a fuzzing technique.

To illustrate this with an example we have chosen the same real-world file manager app from the static analysis section and followed these steps:

1. Send a PDF file from another Apple device (e.g. a MacBook) via Airdrop.
2. Wait for the **AirDrop** popup to appear and click on **Accept**.
3. As there is no default app that will open the file, it switches to the **Open with...** popup. There, we can select the app that will open our file. The next screenshot shows this (we have modified the display name using Frida to conceal the app's real name):

    <img src="Images/Chapters/0x06h/airdrop_openwith.png" width="400px" />

4. After selecting **SomeFileManager** we can see the following:

    ```bash
    (0x1c4077000)  -[AppDelegate application:openURL:options:]
    application: <UIApplication: 0x101c00950>
    openURL: file:///var/mobile/Library/Application%20Support
                        /Containers/com.some.filemanager/Documents/Inbox/OWASP_MASVS.pdf
    options: {
        UIApplicationOpenURLOptionsAnnotationKey =     {
            LSMoveDocumentOnOpen = 1;
        };
        UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
        UIApplicationOpenURLOptionsSourceApplicationKey = "com.apple.sharingd";
        "_UIApplicationOpenURLOptionsSourceProcessHandleKey" = "<FBSProcessHandle: 0x1c3a63140;
                                                                    sharingd:605; valid: YES>";
    }
    0x18c7930d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
    ...
    0x1857cdc34 FrontBoardServices!-[FBSSerialQueue _performNextFromRunLoopSource]
    RET: 0x1
    ```

As you can see, the sending application is `com.apple.sharingd` and the URL's scheme is `file://`. Note that once we select the app that should open the file, the system already moved the file to the corresponding destination, that is to the app's Inbox. The apps are then responsible for deleting the files inside their Inboxes. This app, for example, moves the file to `/var/mobile/Documents/` and removes it from the Inbox.

```bash
(0x1c002c760)  -[XXFileManager moveItemAtPath:toPath:error:]
moveItemAtPath: /var/mobile/Library/Application Support/Containers
                            /com.some.filemanager/Documents/Inbox/OWASP_MASVS.pdf
toPath: /var/mobile/Documents/OWASP_MASVS (1).pdf
error: 0x16f095bf8
0x100f24e90 SomeFileManager!-[AppDelegate __handleOpenURL:]
0x100f25198 SomeFileManager!-[AppDelegate application:openURL:options:]
0x18c7930d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
...
0x1857cd9f4 FrontBoardServices!__FBSSERIALQUEUE_IS_CALLING_OUT_TO_A_BLOCK__
RET: 0x1
```

If you look at the stack trace, you can see how `application:openURL:options:` called `__handleOpenURL:`, which called `moveItemAtPath:toPath:error:`. Notice that we have now this information without having the source code for the target app. The first thing that we had to do was clear: hook `application:openURL:options:`. Regarding the rest, we had to think a little bit and come up with methods that we could start tracing and are related to the file manager, for example, all methods containing the strings "copy", "move", "remove", etc. until we have found that the one being called was `moveItemAtPath:toPath:error:`.

A final thing worth noticing here is that this way of handling incoming files is the same for custom URL schemes. Please refer to @MASTG-TEST-0075 for more information.
