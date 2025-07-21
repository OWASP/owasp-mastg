---
masvs_category: MASVS-STORAGE
platform: ios
title: File System APIs
---

The FileManager interface lets you examine and change the contents of the file system. You can use [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)) to create a file and write to it.

The following example shows how to store a file in the app's documents directory with complete protection, meaning that the file is encrypted and can only be accessed when the device is unlocked.

```swift
FileManager.default.createFile(
    atPath: filePath,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

You can find more information in the Apple Developer Documentation ["Encrypting Your App's Files"](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files "Encrypting Your App's Files")
