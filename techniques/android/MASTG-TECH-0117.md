--- 
title: Obtaining Information from the AndroidManifest
platform: android 
---

The [AndroidManifest.xml](../../Document/0x05a-Platform-Overview.md) file is a critical component of any Android application, providing essential information about the app's structure, permissions, components, and configurations. During a security assessment, analyzing the manifest can reveal potential vulnerabilities or misconfigurations that could be exploited by attackers.

The AndroidManifest is stored in a binary XML format and cannot simply be extracted from the APK by unzipping it. To properly analyze the manifest, you first need to extract and decode it into a human-readable XML format.

Different tools extract the manifest in various formats, with some preserving more raw structure while others interpret or modify it during decoding.

## Using @MASTG-TOOL-0018

Use jadx CLI with `--no-src` to extract only resources without decompiling all sources:

```sh
jadx --no-src -d out_dir MASTG-DEMO-0001.apk
```

jadx outputs the manifest in full to `out_dir/resources/AndroidManifest.xml`, including the `<uses-sdk>` element which is not included when using other tools like apktool.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" ...>
    <uses-sdk
        android:minSdkVersion="29"
        android:targetSdkVersion="35" />
```

## Using @MASTG-TOOL-0011

The AndroidManifest can be extracted using apktool:

```sh
$ apktool d -s -f -o output_dir MASTG-DEMO-0001.apk
I: Using Apktool 2.11.1 on MASTG-DEMO-0001.apk with 8 threads
I: Copying raw classes.dex file...
...
I: Loading resource table...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
```

`-s` skips baksmaliing the dex files and is faster.

The AndroidManifest.xml is extracted and decoded to `output_dir/AndroidManifest.xml`, where you can simply open and view it.

When you decode an APK with apktool, you might notice that the `<uses‑sdk>` element (which includes `minSdkVersion` and `targetSdkVersion`) is missing from the decompiled AndroidManifest.xml. That's expected behavior.

Apktool moves those values into a separate file called apktool.yml rather than inserting them into the decoded XML manifest. In that file you'll see something like:

```yml
sdkInfo:
  minSdkVersion: 29
  targetSdkVersion: 35
```

## Using @MASTG-TOOL-0124

If you are only interested in specific values of the manifest, you can use aapt2.

Note that **the output is not an XML file**.

```bash
$ aapt2 d badging MASTG-DEMO-0001.apk
package: name='org.owasp.mastestapp' versionCode='1' versionName='1.0' platformBuildVersionName='15' platformBuildVersionCode='35' compileSdkVersion='35' compileSdkVersionCodename='15'
sdkVersion:'29'
targetSdkVersion:'35'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
application-label:'MASTestApp'
...
```
