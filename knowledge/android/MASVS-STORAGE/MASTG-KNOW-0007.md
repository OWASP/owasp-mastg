---
masvs_category: MASVS-STORAGE
platform: android
title: Internal Storage
---

You can save files to the device's [internal storage](https://developer.android.com/training/data-storage#filesInternal "Using Internal Storage"). Files saved to internal storage are containerized by default and cannot be accessed by other apps on the device. When the user uninstalls your app, these files are removed.

For example, the following Kotlin snippet stores sensitive information in clear text to a file `sensitive_info.txt` residing on internal storage.

```kotlin
val fileName = "sensitive_info.txt"
val fileContents = "This is some top-secret information!"
File(filesDir, fileName).bufferedWriter().use { writer ->
    writer.write(fileContents)
}
```

You should check the file mode to make sure that only the app can access the file. You can set this access with `MODE_PRIVATE`. Modes such as `MODE_WORLD_READABLE` (deprecated) and `MODE_WORLD_WRITEABLE` (deprecated) may pose a security risk.

**Android Security Guidelines**: Android highlights that the data in the internal storage is private to the app and other apps cannot access it. It also recommends avoiding the use of `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` modes for IPC files and use a [content provider](https://developer.android.com/privacy-and-security/security-tips#content-providers) instead. See the [Android Security Guidelines](https://developer.android.com/privacy-and-security/security-tips#internal-storage "Android Security Guidelines"). Android also provides a [guide](https://developer.android.com/privacy-and-security/security-best-practices#internal-storage "Store data in internal storage based on use case") on how to use internal storage securely.
