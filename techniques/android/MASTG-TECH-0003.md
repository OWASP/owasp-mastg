---
title: Obtaining and Extracting Apps
platform: android
---

There are several ways of extracting APK files from a device. You will need to decide which one is the easiest method depending if the app is public or private.

## Alternative App Stores

One of the easiest options is to download the APK from websites that mirror public applications from the Google Play Store. However, keep in mind that these sites are not official and there is no guarantee that the application hasn't been repackaged or contain malware. A few reputable websites that host APKs and are not known for modifying apps and even list SHA-1 and SHA-256 checksums of the apps are:

- [APKMirror](https://apkmirror.com "APKMirror")
- [APKPure](https://apkpure.com "APKPure")

Beware that you do not have control over these sites and you cannot guarantee what they do in the future. Only use them if it's your only option left.

## Using gplaycli

You can use @MASTG-TOOL-0016 to download (`-d`) the selected APK by specifying its AppID (add `-p` to show a progress bar and `-v` for verbosity):

```bash
$ gplaycli -p -v -d com.google.android.keep
[INFO] GPlayCli version 3.26 [Python3.7.4]
[INFO] Configuration file is ~/.config/gplaycli/gplaycli.conf
[INFO] Device is bacon
[INFO] Using cached token.
[INFO] Using auto retrieved token to connect to API
[INFO] 1 / 1 com.google.android.keep
[################################] 15.78MB/15.78MB - 00:00:02 6.57MB/s/s
[INFO] Download complete
```

The `com.google.android.keep.apk` file will be in your current directory. As you might imagine, this approach is a very convenient way to download APKs, especially with regards to automation.

> You may use your own Google Play credentials or token. By default, gplaycli will use [an internally provided token](https://github.com/matlink/gplaycli/blob/3.26/gplaycli/gplaycli.py#L106 "gplaycli Fallback Token").

## Extracting the App Package from the Device

Obtaining app packages from the device is the recommended method as we can guarantee the app hasn't been modified by a third-party. To obtain applications from a rooted or non-rooted device, you can use the following methods:

Use `adb pull` to retrieve the APK. If you don't know the package name, the first step is to list all the applications installed on the device:

```bash
adb shell pm list packages
```

Once you have located the package name of the application, you need the full path where it is stored on the system to download it.

```bash
adb shell pm path <package name>
```

With the full path to the APK, you can now simply use `adb pull` to extract it.

```bash
adb pull <apk path>
```

The APK will be downloaded in your working directory.

Alternatively, there are also apps like [APK Extractor](https://github.com/Domilopment/apk-extractor "APK Extractor") that do not require root and can even share the extracted APK via your preferred method. This can be useful if you don't feel like connecting the device or setting up adb over the network to transfer the file.

## Testing Instant Apps

With [Google Play Instant](https://developer.android.com/topic/google-play-instant/overview "Google Play Instant") you can create Instant apps which can be instantly launched from a browser or the "try now" button from the app store from Android 5.0 (API level 21) onward. They do not require any form of installation. There are a few challenges with an instant app:

- There is a limited amount of size you can have with an instant app.
- Only a reduced number of permissions can be used, which are documented at [Android Instant app documentation](https://developer.android.com/topic/google-play-instant/getting-started/instant-enabled-app-bundle?tenant=irina#request-supported-permissions "Permission documentation for Android Instant Apps").

The combination of these can lead to insecure decisions, such as: stripping too much of the authorization/authentication/confidentiality logic from an app, which allows for information leakage.

Note: Instant apps require an App Bundle. App Bundles are described in the "[App Bundles](../../Document/0x05a-Platform-Overview.md#app-bundles)" section of the "Android Platform Overview" chapter.

**Static Analysis Considerations:**

Static analysis can be either done after reverse engineering a downloaded instant app, or by analyzing the App Bundle. When you analyze the App Bundle, check the Android Manifest to see whether `dist:module dist:instant="true"` is set for a given module (either the base or a specific module with `dist:module` set). Next, check for the various entry points, which entry points are set (by means of `<data android:path="</PATH/HERE>" />`).

Now follow the entry points, like you would do for any Activity and check:

- Is there any data retrieved by the app which should require privacy protection of that data? If so, are all required controls in place?
- Are all communications secured?
- When you need more functionalities, are the right security controls downloaded as well?

**Dynamic Analysis Considerations:**

There are multiple ways to start the dynamic analysis of your instant app. In all cases, you will first have to install the support for instant apps and add the `ia` executable to your `$PATH`.

The installation of instant app support is taken care off through the following command:

```bash
cd path/to/android/sdk/tools/bin && ./sdkmanager 'extras;google;instantapps'
```

Next, you have to add `path/to/android/sdk/extras/google/instantapps/ia` to your `$PATH`.

After the preparation, you can test instant apps locally on a device running Android 8.1 (API level 27) or later. The app can be tested in different ways:

- Test the app locally:
  Deploy the app via Android Studio (and enable the `Deploy as instant app` checkbox in the Run/Configuration dialog) or deploy the app using the following command:

  ```bash
  ia run output-from-build-command <app-artifact>
  ```

- Test the app using the Play Console:
  1. Upload your App Bundle to the Google Play Console
  2. Prepare the uploaded bundle for a release to the internal test track.
  3. Sign into an internal tester account on a device, then launch your instant experience from either an external prepared link or via the `try now` button in the App store from the testers account.

Now that you can test the app, check whether:

- There are any data which require privacy controls and whether these controls are in place.
- All communications are sufficiently secured.
- When you need more functionalities, are the right security controls downloaded as well for these functionalities?
