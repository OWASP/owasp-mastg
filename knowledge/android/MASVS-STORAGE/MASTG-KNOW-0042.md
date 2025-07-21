---
masvs_category: MASVS-STORAGE
platform: android
title: External Storage
---

Android devices support [shared external storage](https://developer.android.com/training/data-storage#filesExternal "Using External Storage"). This storage may be removable (such as an SD card) or emulated (non-removable). A malicious app with proper permissions running on Android 10 or below can access data that you write to "external" [app-specific-directories](https://developer.android.com/training/data-storage/app-specific). The user can also modify these files when USB mass storage is enabled.

The files stored in these directories are [removed when your app is uninstalled](https://developer.android.com/training/data-storage/app-specific#external).

External storage must be used carefully as there are many risks associated with it. For example an attacker may be able to retrieve sensitive data or [obtain arbitrary control of the application](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/ "Man in the disk").

**Android Security Guidelines**: Android recommends not storing sensitive data on external storage and to perform input validation on all data stored on external storage. See the [Android Security Guidelines](https://developer.android.com/privacy-and-security/security-tips#external-storage "Android Security Guidelines"). Android also provides a [guide](https://developer.android.com/privacy-and-security/security-best-practices#external-storage "Store data in external storage based on use case") on how to use external storage securely.

## Scoped Storage

To give users more control over their files and to limit file clutter, apps that target Android 10 (API level 29) and higher are given scoped access into external storage, or [scoped storage](https://developer.android.com/training/data-storage#scoped-storage), by default. When scoped storage is enabled, apps cannot access the app-specific directories that belong to other apps.

The Android developers documentation provides a detailed guide highlighting common [storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases) differentiating between handling media and non-media files and considering scoped storage.

**Opting out**: Apps targeting Android 10 (API level 29) or lower can [temporarily opt out of scoped storage](https://developer.android.com/training/data-storage/use-cases#opt-out-in-production-app) using `android:requestLegacyExternalStorage="true"` in their app manifest. Once the app targets Android 11 (API level 30), the system ignores the `requestLegacyExternalStorage` attribute when running on Android 11 devices.

> [App attribution for media files (Android Developers)](https://developer.android.com/training/data-storage/shared/media#app-attribution):
> When [scoped storage](https://developer.android.com/training/data-storage#scoped-storage) is enabled for an app that targets Android 10 or higher, the system attributes an app to each media file, which determines the files that your app can access when it hasn't requested any storage permissions. Each file can be attributed to only one app. Therefore, if your app creates a media file that's stored in the photos, videos, or audio files media collection, your app has access to the file.
>
> If the user uninstalls and reinstalls your app, however, you must request [READ_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#READ_EXTERNAL_STORAGE) to access the files that your app originally created. This permission request is required because the system considers the file to be attributed to the previously installed version of the app, rather than the newly installed one.

For example, trying to access a file stored using the `MediaStore` API with a `content://` URI like `content://media/external_primary` would only work as long as the image _belongs_ to the invoking app (due to `owner_package_name` attribute in the `MediaStore`). If the app calls a `content://` URI that does not belong to the app, it will fail with a `SecurityException`:

```sh
Cannot open content uri: content://media/external_primary/images/media/1000000041
java.lang.SecurityException: org.owasp.mastestapp has no access to content://media/external_primary/images/media/1000000041
```

You can validate this by querying the MediaStore via adb, for example:

- `adb shell content query --uri content://media/external_primary/images/media`
- `adb shell content query --uri content://media/external_primary/file`

To be able to access the content, the app must have the necessary permissions e.g., `READ_EXTERNAL_STORAGE` before Android 10 API level 29, `READ_MEDIA_IMAGES` or `MANAGE_EXTERNAL_STORAGE` from Android 10 API level 29 onwards.

> `READ_EXTERNAL_STORAGE` is deprecated (and is not granted) when targeting Android 13 (API level 33) and above. If you need to query or interact with MediaStore or media files on the shared storage, you should instead use one or more new storage permissions: `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` or `READ_MEDIA_AUDIO`.
>
> Scoped storage is enforced starting on Android 10 (API level 29) (or Android 11 if using `requestLegacyExternalStorage`). In particular, `WRITE_EXTERNAL_STORAGE` will no longer provide write access to all files; it will provide the equivalent of `READ_EXTERNAL_STORAGE` instead.
>
> As of Android 13 (API level 33), if you need to query or interact with MediaStore or media files on the shared storage, you should be using instead one or more new storage permissions: `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` or `READ_MEDIA_AUDIO`.

After declaring the permission in the manifest you can grant it with adb:

```sh
adb shell pm grant org.owasp.mastestapp android.permission.READ_MEDIA_IMAGES
```

You can revoke the permission with:

```sh
adb shell pm revoke org.owasp.mastestapp android.permission.READ_MEDIA_IMAGES
```

## External Storage APIs

There are APIs such as [`getExternalStoragePublicDirectory`](https://developer.android.com/reference/kotlin/android/os/Environment#getExternalStoragePublicDirectory(kotlin.String)) that return paths to a shared location that other apps can access. An app may obtain a path to an "external" location and write sensitive data to it. This location is considered "Shared Storage Requiring No User Interaction", which means that a third-party app with proper permissions can read this sensitive data.

For example, the following Kotlin snippet stores sensitive information in clear text to a file `password.txt` residing on external storage.

```kotlin
val password = "SecretPassword"
val path = context.getExternalFilesDir(null)
val file = File(path, "password.txt")
file.appendText(password)
```

## MediaStore API

The [`MediaStore` API](https://developer.android.com/training/data-storage/shared/media) provides a way for apps to interact with two types of files stored on the device:

- media files including images (`MediaStore.Images`), videos (`MediaStore.Video`), audio (`MediaStore.Audio`) and downloads (`MediaStore.Downloads`), and
- non-media files (e.g. text, HTML, PDF, etc.) stored in the `MediaStore.Files` collection.

Using this API requires a `ContentResolver` object retrieved from the app's Context. See an example in the [Android Developers documentation](https://developer.android.com/training/data-storage/shared/media#media_store).

**Apps running on Android 9 (API level 28) or lower:**

- They can access the app-specific files that belong to other apps if they have opted out of scoped storage and requested the `READ_EXTERNAL_STORAGE` permission.
- To modify the files, the app must also request the `WRITE_EXTERNAL_STORAGE` permission.

**Apps running on Android 10 (API level 29) or higher:**

- **Accessing own media files:**
    - Apps can always [access their own media files](https://developer.android.com/training/data-storage/shared/media#storage-permission-not-always-needed) stored using the `MediaStore` API without needing any storage-related permissions. This includes files in the app-specific directories within external storage (scoped storage) and files in the MediaStore that the app created.

- **Accessing other apps' media files:**
    - Apps require certain permissions and APIs to [access media files that belong to other apps](https://developer.android.com/training/data-storage/shared/media#access-other-apps-files).
    - If scoped storage is enabled, apps can't access the app-specific media files that belong to other apps. However, if scoped storage is disabled, apps can access the app-specific media files that belong to other apps using the `MediaStore.Files` query.

- **Accessing downloads (`MediaStore.Downloads` collection):**
    - To access downloads from other apps, the app must use the [Storage Access Framework](https://developer.android.com/training/data-storage/shared/documents-files).

## Manifest Permissions

Android defines the following [permissions for accessing external storage](https://developer.android.com/training/data-storage#permissions): [`READ_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#READ_EXTERNAL_STORAGE), [`WRITE_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#WRITE_EXTERNAL_STORAGE) and [`MANAGE_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#MANAGE_EXTERNAL_STORAGE).

An app must declare in the Android Manifest file an intention to write to shared locations. Below you can find a list of such manifest permissions:

- [`READ_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#READ_EXTERNAL_STORAGE): allows an app to read from external storage.
    - **Before Android 4.4 (API level 19)**, this permission is not enforced and all apps have access to read the entire external storage (including files from other apps).
    - **Starting on Android 4.4 (API level 19)**, apps don't need to request this permission to access their own app-specific directories within external storage.
    - **Starting on Android 10 (API level 29)**, [scoped storage](https://developer.android.com/training/data-storage#scoped-storage) applies by default:
        - Apps **cannot read the app-specific directories that belong to other apps** (which was possible before when having `READ_EXTERNAL_STORAGE` granted).
        - Apps don't need to have this permission to read files from their own app-specific directories within external storage (scoped storage), or their own files in the MediaStore.
    - **Starting on Android 13 (API level 33)**, this permission **has no effect**. If needing to access media files from other apps, apps must request one or more of these permissions: `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, or `READ_MEDIA_AUDIO`.

- [`WRITE_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#WRITE_EXTERNAL_STORAGE): allows an app to write a file to the "external storage", regardless of the actual storage origin (external disk or internally emulated by the system).
    - **Starting on Android 4.4 (API level 19)**, apps don't need to request this permission to access their own app-specific directories within external storage.
    - **Starting on Android 10 (API level 29)**, [scoped storage](https://developer.android.com/training/data-storage#scoped-storage) applies by default:
        - Apps **cannot write to the app-specific directories that belong to other apps** (which was possible before when having `WRITE_EXTERNAL_STORAGE` granted).
        - Apps don't need this permission to write files in their own app-specific directories within external storage.
    - **Starting on Android 11 (API level 30)**, this permission is **deprecated and has no effect**, but can be preserved with [requestLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#requestLegacyExternalStorage) and [preserveLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#preserveLegacyExternalStorage).

- [`MANAGE_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission#MANAGE_EXTERNAL_STORAGE): Some apps require [broad access to all files](https://developer.android.com/training/data-storage/manage-all-files).
    - This permission only applies to apps targeting Android 11.0 (API level 30) or higher.
    - Usage of this permission is **restricted by Google Play** unless the app satisfies [certain requirements](https://support.google.com/googleplay/android-developer/answer/10467955) and requires **special app access** called ["All files access"](https://developer.android.com/preview/privacy/storage#all-files-access).
    - Scoped storage doesn't affect the app's ability to access app-specific directories when having this permission.

- [`READ_MEDIA_IMAGES`](https://developer.android.com/reference/android/Manifest.permission#READ_MEDIA_IMAGES), [`READ_MEDIA_VIDEO`](https://developer.android.com/reference/android/Manifest.permission#READ_MEDIA_VIDEO) and [`READ_MEDIA_AUDIO`](https://developer.android.com/reference/android/Manifest.permission#READ_MEDIA_AUDIO): allow an app to read media files from the `MediaStore` collection.
    - **Starting on Android 13 (API level 33)**, since `READ_EXTERNAL_STORAGE` **has no effect**, these permissions are required to access media files from the `MediaStore.Images`, `MediaStore.Video`, and `MediaStore.Audio` collections respectively.
