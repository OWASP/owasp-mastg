--- 
title: Obtaining Information from the AndroidManifest
platform: android 
---

Multiple ways exist to view the contents of the AndroidManifest:

## Using @MASTG-TOOL-0011

The full AndroidManifest can be extracted using @MASTG-TOOL-0011:

```sh
$ apktool d myapp.apk -s -o apktooled_app
I: Using Apktool 2.7.0 on myapp.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Copying raw classes.dex file...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
```

`-s` skips baksmaliing the dex files and is faster.

The AndroidManifest.xml is extracted and decoded to `apktooled_app/AndroidManifest.xml`, where you can simply open and view it.

## Using @MASTG-TOOL-0124

If you are only interested in specific values of the manifest, you can use alternatively use @MASTG-TOOL-0124. Please note that the output is not a XML file.

Viewing all contents of the AndroidManifest can be performed with:

```bash
$ aapt d badging MASTG-DEMO-0001.apk                     
package: name='org.owasp.mastestapp' versionCode='1' versionName='1.0' platformBuildVersionName='14' platformBuildVersionCode='34' compileSdkVersion='34' compileSdkVersionCodename='14'
sdkVersion:'29'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
application-label:'MASTestApp'
...
```
