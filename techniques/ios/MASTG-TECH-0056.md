---
title: Installing Apps
platform: ios
---

When you install an application without using Apple's App Store, this is called sideloading. There are various ways of sideloading which are described below. On the iOS device, the actual installation process is then handled by the installd daemon, which will unpack and install the application. To integrate app services or be installed on an iOS device, all applications must be signed with a certificate issued by Apple. This means that the application can be installed only after successful code signature verification, which is explained in @MASTG-TECH-0092.

On a jailbroken device, you can circumvent this requirement using @MASTG-TOOL-0127, allowing you to install IPA files without obtaining a valid signature.

Different methods exist for installing an IPA package onto an iOS device, which are described in detail below.

## Sideloadly

@MASTG-TOOL-0118 is a GUI tool that can automate all required steps for you. It requires valid Apple developer credentials, as it will obtain a valid signature from Apple servers.

Simply connect your device via USB, enter your Apple ID and drag-and-drop the IPA file onto SideLoadly. Click start to automatically sign and install the given IPA.

<img src="Images/Techniques/0056-Sideloadly.png" width="400px" />

## libimobiledevice

On Linux and also macOS, you can alternatively use @MASTG-TOOL-0126. This allows you to install apps over a USB connection by executing ideviceinstaller. The connection is implemented with the USB multiplexing daemon [usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux "Usbmux"), which provides a TCP tunnel over USB.

Let's install and debug the @MASTG-APP-0028 app with the following commands:

```bash
$ ideviceinstaller -i Uncrackable.ipa
...
Install: Complete
```

## ipainstaller

The IPA can also be directly installed on the iOS device via the command line with [ipainstaller](https://github.com/autopear/ipainstaller "IPA Installer"). Naturally, this requires a jailbroken device, as otherwise you cannot SSH into the device. After copying the file over to the device, for example via scp, you can execute ipainstaller with the IPA's filename:

```bash
ipainstaller Uncrackable.ipa
```

## ios-deploy

On macOS you can also use the @MASTG-TOOL-0054 tool to install iOS apps from the command line. You'll need to unzip your IPA since ios-deploy uses the app bundles to install apps.

```bash
unzip Name.ipa
ios-deploy --bundle 'Payload/UnCrackable Level 1.app' -W -v
```

## Xcode

It is also possible to use the Xcode IDE to install iOS apps by executing the following steps:

1. Start Xcode
2. Select **Window/Devices and Simulators**
3. Select the connected iOS device and click on the **+** sign in **Installed Apps**.

## Allow Application Installation on a Non-iPad Device

Sometimes an application can require to be used on an iPad device. If you only have iPhone or iPod touch devices then you can force the application to accept to be installed and used on these kinds of devices. You can do this by changing the value of the property **UIDeviceFamily** to the value **1** in the **Info.plist** file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

  <key>UIDeviceFamily</key>
  <array>
    <integer>1</integer>
  </array>

</dict>
</plist>
```

It is important to note that changing this value will break the original signature of the IPA file so you need to re-sign the IPA, after the update, in order to install it on a device on which the signature validation has not been disabled.

This bypass might not work if the application requires capabilities that are specific to modern iPads while your iPhone or iPod is a bit older.

Possible values for the property [UIDeviceFamily](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW11 "UIDeviceFamily property") can be found in the Apple Developer documentation.
