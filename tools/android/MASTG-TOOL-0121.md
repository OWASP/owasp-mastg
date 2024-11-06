---
title: aapt2
platform: android
source: https://play.google.com/store/apps/details?id=org.proxydroid&hl=en
---

Android Asset Packaging tool (aapt2) is contained in the @MASTG-TOOL-0006 within the build-tools folder. 

It requires an APK file as input and can be used for example to examine the contents of the AndroidManifest file.

The permissions of an APK file can be viewed with:

```bash
$ aapt d permissions app-x86-debug.apk
package: sg.vp.owasp_mobile.omtg_android
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.INTERNET'
```

Viewing all contents of the AndroidManifest can be performed with:

```bash
$ aapt d badging app-x86-debug.apk
package: name='sg.vp.owasp_mobile.omtg_android' versionCode='1' versionName='1.0' compileSdkVersion='34' compileSdkVersionCodename='14'
sdkVersion:'23'
targetSdkVersion:'34'
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.INTERNET'
application-label:'OMTG Android'
...
```
