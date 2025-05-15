---
title: Performing a Backup and Restore of App Data
platform: android 
---

## Using the Backup Manager (via ADB shell)

Run [Backup Manager (`adb shell bmgr`)](https://developer.android.com/identity/data/testingbackup#TestingBackup)

{{ ../../utils/mastg-android-backup-bmgr.sh }}

When using the cloud transport variant, each app's backup is managed and stored independently in the user's Google Drive. In our case we're interested in the local transport variant, where `bmgr` stores each app's backup data in a separate `.ab` file within the `/data/data/com.android.localtransport/files/` directory on the device. To extract the file run:

```sh
adb root
adb pull /data/data/com.android.localtransport/files/1/_full/org.owasp.mastestapp org.owasp.mastestapp.ab
tar xvf org.owasp.mastestapp.ab
```

The extracted backup directory (`apps/`) is stored in the current working directory. For instructions on how to inspect it, see @MASTG-TECH-0127.

## Using ADB Backup

!!! warning
    `adb backup` is [restricted since Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions) and requires `android:debuggable=true` in the AndroidManifest.xml.

You can run `adb backup` to back up the app data. Approve the backup from your device by selecting the _Back up my data_ option. After the backup process is finished, the file _.ab_ will be in your working directory.

{{ ../../utils/mastg-android-backup-adb.sh }}

The extracted backup directory (`apps/`) is stored in the current working directory. For instructions on how to inspect it, see @MASTG-TECH-0127.

**Note:** The behavior might differ between an emulator and a physical device.

## Using Android Backup Extractor

You can use [Android Backup Extractor](https://github.com/nelenkov/android-backup-extractor) to extract the backup data. For more information, refer to its GitHub repo.
