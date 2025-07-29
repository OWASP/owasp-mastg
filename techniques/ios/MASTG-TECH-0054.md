---
title: Obtaining and Extracting Apps
platform: ios
---

## Getting the IPA File from an OTA Distribution Link

During development, apps are sometimes provided to testers via over-the-air (OTA) distribution. In that situation, you'll receive an itms-services link, such as the following:

```default
itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist
```

You can use the [ITMS services asset downloader](https://www.npmjs.com/package/itms-services "ITMS services asset downloader") tool to download the IPA from an OTA distribution URL. Install it via npm:

```bash
npm install -g itms-services
```

Save the IPA file locally with the following command:

```bash
# itms-services -u "itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist" -o - > out.ipa
```

## Extracting the App Binary

If you have an IPA with a decrypted app binary, unzip it and you are ready to go. The app binary is located in the main bundle directory (.app), e.g. `Payload/Telegram X.app/Telegram X`. See the following subsection for details on the extraction of the property lists.

> On macOS's Finder, .app directories are opened by right-clicking them and selecting "Show Package Content". On the terminal you can just `cd` into them.

## Decrypting the App Binary

>**IMPORTANT NOTE:** In the United States, the Digital Millennium Copyright Act 17 U.S.C. 1201, or DMCA, makes it illegal and actionable to circumvent certain types of DRM. However, the DMCA also provides exemptions, such as for certain kinds of security research. A qualified attorney can help you determine if your research qualifies under the DMCA exemptions. (Source: [Corellium](https://support.corellium.com/en/articles/6181345-testing-third-party-ios-apps))

If you don't have the original IPA, then you need a jailbroken device where you will install the app (e.g. via App Store). Once installed, you need to extract the app binary from memory and rebuild the IPA file. Because of DRM, **the app binary file is encrypted** when it is stored on the iOS device, so simply pulling it from the Bundle (either through SSH or Objection) will not be sufficient to reverse engineer it.

You can verify this by running this command on the app binary:

```bash
otool -l Payload/Telegram X.app/Telegram X | grep -i LC_ENCRYPTION -B1 -A4
Load command 12
          cmd LC_ENCRYPTION_INFO
      cmdsize 20
     cryptoff 16384
    cryptsize 32768
      cryptid 1
```

Or with @MASTG-TOOL-0129:

```bash
rabin2 -I Payload/Telegram X.app/Telegram X | grep crypto
crypto   true
```

In order to retrieve the unencrypted version, you can use [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump "frida-ios-dump"). It will extract the unencrypted version from memory while the application is running on the device.

First, configure @MASTG-TOOL-0050 `dump.py`:

- set it to use `localhost` with port `2222` when using @MASTG-TOOL-0055 (`iproxy 2222 22`), or to the actual IP address and port of the device from which you want to dump the binary.
- update the default username (`User = 'root'`) and password (`Password = 'alpine'`) in `dump.py` to the ones you have set.

Enumerate the apps installed on the device by running `python dump.py -l`:

```bash
 PID  Name             Identifier
----  ---------------  -------------------------------------
 860  Cydia            com.saurik.Cydia
1130  Settings         com.apple.Preferences
 685  Mail             com.apple.mobilemail
 834  Telegram         ph.telegra.Telegraph
   -  Stocks           com.apple.stocks
   ...
```

You can dump the selected app, for example Telegram, by running `python dump.py -H 127.0.0.1 -p 2222 --user mobile -P alpine ph.telegra.Telegraph`, if you are using an SSH tunnel with `iproxy` and the default credentials on a jailbroken phone.

After a couple of seconds, the `Telegram.ipa` file will be created in your current directory. You can validate the success of the dump by removing the app and reinstalling it (e.g. using @MASTG-TOOL-0054 `ios-deploy -b Telegram.ipa`). Note that this will only work on jailbroken devices, as otherwise the signature won't be valid.

You can use @MASTG-TOOL-0129 to verify that the app binary is now unencrypted:

```bash
rabin2 -I Payload/Telegram X.app/Telegram X | grep crypto
crypto   false
```

## Thinning the App Binary

The app binary may contain multiple architectures, such as `armv7` (32-bit) and `arm64` (64-bit). That is called a "fat binary".

One example is the [Damn Vulnerable iOS App DVIA v1](https://github.com/prateek147/DVIA/) to demonstrate this.

Unzip the app and run @MASTG-TOOL-0060:

```bash
unzip DamnVulnerableiOSApp.ipa
cd Payload/DamnVulnerableIOSApp.app
otool -hv DamnVulnerableIOSApp
```

The output will look like this:

```bash
DamnVulnerableIOSApp (architecture armv7):
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC      ARM         V7  0x00     EXECUTE    33       3684   NOUNDEFS DYLDLINK TWOLEVEL PIE
DamnVulnerableIOSApp (architecture arm64):
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    33       4192   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

To ease the app analysis, it's recommended create a so-called thin binary, which contains one architecture only:

```bash
lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
```
