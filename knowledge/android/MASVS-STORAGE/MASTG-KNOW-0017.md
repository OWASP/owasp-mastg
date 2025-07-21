---
masvs_category: MASVS-STORAGE
platform: android
title: Backups
---

[Android backups](https://developer.android.com/identity/data/backup) usually include copies of data and settings for all installed apps. Given its diverse ecosystem, Android supports many backup options:

- Stock Android has built-in USB backup facilities. When USB debugging is enabled, use the `adb backup` command ([restricted since Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions), requires `android:debuggable=true` in the AndroidManifest.xml) to create full data backups and backups of an app's data directory.

- Google provides a "Back Up My Data" feature that backs up all app data to Google's servers.

- Two Backup APIs are available to app developers:
    - [Key/Value Backup](https://developer.android.com/guide/topics/data/keyvaluebackup.html "Key/Value Backup") (Backup API or Android Backup Service) uploads to the Android Backup Service cloud.

    - [Auto Backup for Apps](https://developer.android.com/guide/topics/data/autobackup.html "Auto Backup for Apps"): With Android 6.0 (API level 23) and above, Google added the "Auto Backup for Apps feature". This feature automatically syncs at most 25MB of app data with the user's Google Drive account.

- OEMs may provide additional options. For example, HTC devices have a "HTC Backup" option that performs daily backups to the cloud when activated.

Apps must carefully ensure that sensitive user data doesn't end within these backups as this may allow an attacker to extract it.

## ADB Backup Support

Android provides an attribute called [`allowBackup`](https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup "allowBackup attribute") to back up all your application data. This attribute is set in the `AndroidManifest.xml` file. If the value of this attribute is **true**, the device allows users to back up the application with Android Debug Bridge (ADB) via the command `$ adb backup` ([restricted in Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)).

To prevent the app data backup, set the `android:allowBackup` attribute to **false**. When this attribute is unavailable, the allowBackup setting is enabled by default, and backup must be manually deactivated.

> Note: If the device was encrypted, then the backup files will be encrypted as well.
