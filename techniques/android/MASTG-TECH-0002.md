---
title: Host-Device Data Transfer
platform: android
---

## Using adb

You can copy files to and from a device by using the @MASTG-TOOL-0004 commands `adb pull <remote> <local>` and `adb push <local> <remote>` [commands](https://developer.android.com/studio/command-line/adb#copyfiles "Copy files to/from a device"). Their usage is very straightforward. For example, the following will copy `foo.txt` from your current directory (local) to the `sdcard` folder (remote):

```bash
adb push foo.txt /sdcard/foo.txt
```

This approach is commonly used when you know exactly what you want to copy and from/to where and also supports bulk file transfer, e.g. you can pull (copy) a whole directory from the Android device to your host computer.

```bash
$ adb pull /sdcard
/sdcard/: 1190 files pulled. 14.1 MB/s (304526427 bytes in 20.566s)
```

## Using Android Studio Device File Explorer

Android Studio has a [built-in Device File Explorer](https://developer.android.com/studio/debug/device-file-explorer "Device File Explorer") which you can open by going to **View** -> **Tool Windows** -> **Device File Explorer**.

<img src="Images/Chapters/0x05b/android-studio-file-device-explorer.png" width="400px" />

If you're using a rooted device you can now start exploring the whole file system. However, when using a non-rooted device accessing the app sandboxes won't work unless the app is debuggable and even then you are "jailed" within the app sandbox.

## Using objection

This option is useful when you are working on a specific app and want to copy files you might encounter inside its sandbox (notice that you'll only have access to the files that the target app has access to). This approach works without having to set the app as debuggable, which is otherwise required when using Android Studio's Device File Explorer.

First, connect to the app with Objection as explained in @MASTG-TOOL-0038. Then, use `ls` and `cd` as you normally would on your terminal to explore the available files:

```bash
$ frida-ps -Ua | grep -i owasp
21228  Attack me if u can  sg.vp.owasp_mobile.omtg_android  

$ objection -n "Attack me if u can" start

...g.vp.owasp_mobile.omtg_android on (google: 8.1.0) [usb] # cd ..
/data/user/0/sg.vp.owasp_mobile.omtg_android

...g.vp.owasp_mobile.omtg_android on (google: 8.1.0)  [usb] # ls
Type       ...  Name
---------  ...  -------------------
Directory  ...  cache
Directory  ...  code_cache
Directory  ...  lib
Directory  ...  shared_prefs
Directory  ...  files
Directory  ...  app_ACRA-approved
Directory  ...  app_ACRA-unapproved
Directory  ...  databases

Readable: True  Writable: True
```

One you have a file you want to download you can just run `filesystem download <some_file>`. This will download that file to your working directory. The same way you can upload files using `filesystem upload`.

```bash
...[usb] # ls
Type    ...  Name
------  ...  -----------------------------------------------
File    ...  sg.vp.owasp_mobile.omtg_android_preferences.xml

Readable: True  Writable: True
...[usb] # filesystem download sg.vp.owasp_mobile.omtg_android_preferences.xml
Downloading ...
Streaming file from device...
Writing bytes to destination...
Successfully downloaded ... to sg.vp.owasp_mobile.omtg_android_preferences.xml

```

As per objection v1.12.0, objection does support downloading folders by using the strict syntax `filesystem download <remote folder> <local destination> --folder`. However this only applies to folders and does not allow specifying multiple individual files directly. 

```bash
...[usb] # filesystem download databases dbs --folder
Downloading /data/user/0/sg.vp.owasp_mobile.omtg_android/databases to dbs
Do you want to download the full directory? [Y/n]: 
Downloading directory recursively...
Successfully downloaded /data/user/0/sg.vp.owasp_mobile.omtg_android/databases/College to dbs/College
Successfully downloaded /data/user/0/sg.vp.owasp_mobile.omtg_android/databases/College-journal to dbs/College-journal
Successfully downloaded /data/user/0/sg.vp.owasp_mobile.omtg_android/databases/privateNotSoSecure to dbs/privateNotSoSecure
Successfully downloaded /data/user/0/sg.vp.owasp_mobile.omtg_android/databases/privateNotSoSecure-journal to dbs/privateNotSoSecure-journal
Successfully downloaded /data/user/0/sg.vp.owasp_mobile.omtg_android/databases/encrypted to dbs/encrypted
Recursive download finished.

```
Instead of for example taking note of the full path of that file and use `adb pull <path_to_some_file>` from a separate terminal, you might just want to directly do `filesystem download <some_file>`.
