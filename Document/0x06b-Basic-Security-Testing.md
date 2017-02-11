## Basic Security Testing on iOS

### Setting Up Your Testing Environment

### Static Analysis

#### With Source Code

#### Without Source Code

##### Recovering an IPA file from an installed app

###### From Jailbroken devices

You can use Saurik's IPA Installer to recover IPAs from apps installed on the device. To do this, install [IPA installer console](http://cydia.saurik.com/package/com.autopear.installipa/) via Cydia. Then, ssh into the device and look up the bundle id of the target app. For example:

~~~
iPhone:~ root# ipainstaller -l
com.apple.Pages
com.example.targetapp
com.google.ios.youtube
com.spotify.client
~~~

Generate the IPA file for using the following command:

~~~
iPhone:~ root# ipainstaller -b com.example.targetapp -o /tmp/example.ipa
~~~

###### From non-Jailbroken devices

If the app is available on itunes, you are able to recover the ipa on MacOS with the following simple steps:

- Download the app in itunes
- Go to your itunes Apps Library
- Right-click on the app and select show in finder

(... TODO...)

#### Dumping Decrypted Executables

On top of code signing, apps distributed via the app store are also protected using Apple's FairPlay DRM system. This system uses asymmetric cryptography to ensure that any app (including free apps) obtained from the app store only executes on the particular device it is approved to run on. The decryption key is unique to the device and burned into the processor. As of now, the only possible way to obtain the decrypted code from a FairPlay-decrypted app is dumping it from memory while the app is running. On a jailbroken device, this can be done with Stefan Esser's dumpdecrypted tool [1].

Download and compile dumpdecrypted as follows (requires XCode command line tools):

~~~
$ git clone https://github.com/stefanesser/dumpdecrypted
$ cd dumpdecrypted
$ make
~~~

This should create dumpdecrypted.dylib. Copy it to the /usr/lib directory on your device via SSH:

~~~
$ scp dumpdecrypted.dylib root@iphone:/usr/lib/
~~~

Then, connect to the device and run the main executable of the target app while setting the DYLD_INSERT_LIBRARIES environment variable.

~~~
$ ssh root@iphone
iPhone:~ root# cd /usr/lib
iPhone:/usr/lib root#
iPhone:/usr/lib root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib "/var/mobile/Containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEE/Target.app/Target"
~~~

The decrypted binary is saved in the current working directory.

### Dynamic Analysis

#### On Jailbroken devices

#### On Non-Jailbroken Devices

If you don't have access to a jailbroken device, you can patch and repackage the target app to load a dynamic library at startup. This way, you can instrument the app and can do pretty much everything you need for a dynamical analysis (of course, you can't break out of the sandbox that way, but you usually don't need to). This technique however works only on if the app binary isn't FairPlay-encrypted (i.e. obtained from the app store).

Unfortunately, thanks to Apple's confusing provisioning and code signing system, this is more challenging to get this right than one would expect: iOS will refuse to run an app unless you get the provisioning profile and code signature header absolutely right. This requires you to know about a whole lot of concepts - different types of certificates, BundleIDs, application IDs, team identifiers, and how they are tied together using Apple's build tools. Suffice it to say, getting the OS to run a particular binary that hasn't been built using the default way (XCode) can be an exhilarating process.

Example app:

https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/02_iOS/UnCrackable_Level2

##### Getting a Developer Certificate

The *provisioning profile* is a plist file signed by Apple that whitelists your code signing certificate on one or more devices (in other words, Apple generously allows you to run your apps on those devices). The provisioning profile also includes the entitlements granted to your app. The *certificate* contains the private key you'll use to do the actual signing.

For registered iOS developers, certificates and provisioning profiles can be obtained through the iOS Developer Portal [1]. In the following section I'll be using a developer profile associated with my company's Enterprise account. Since Xcode 7, it is also possible to get a free developer certificate without paying for a developer account:

https://livecode.com/how-to-create-a-free-ios-development-provisioning-profile/

In the following section, we'll be assuming you already have set up Xcode and have a certificate available.

~~~
$ security find-identity -p codesigning -v
  1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Vantage Point Security Pte. Ltd."
  2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
~~~

##### Preparations

Building OPTool

http://www.mopsled.com/2016/build-optool-osx/
~~~
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
~~~

~~~
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
~~~

##### Issuing Provisioning Profile

**From the Developer Portal***

"Identifiers -> App IDs"

The App ID string contains two parts separated by a period (.) — an App ID Prefix that is defined as your Team ID by default and an App ID Suffix that is defined as a Bundle ID search string

"Provisioning Profiles -> All" and click the + sign. Choose iOS App Development. Select the app ID created before, your developer account, and the device ID.

This should yield you a file called AwesomeRepackaging.mobileprovision.

**Via XCode***

Follow the instructions in the NCC Group blog artice [3].

##### Patching, Repackaging and Re-Signing

~~~
$ unzip UnCrackable_Level_1.ipa
$ optool install -c load -p FridaGadget.dylib -t Payload/Fuckmeup.app/Fuckmeup
~~~

Get entitlements:

~~~
$ security cms -D -i AwesomeRepackaging.mobileprovision > profile.plist
$ /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
$ cat entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>LRUD9L355Y.sg.vantagepoint.repackage</string>
	<key>com.apple.developer.team-identifier</key>
	<string>LRUD9L355Y</string>
	<key>get-task-allow</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>LRUD9L355Y.*</string>
	</array>
</dict>
</plist>
~~~



~~~
$ rm -rf Payload/F/_CodeSignature
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 2.app/
$ optool install -c load -p FridaGadget.dylib -t Payload/UnCrackable\ Level\ 2.app/UnCrackable\ Level\ 2
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 2.app/UnCrackable Level 2...
~~~



~~~
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 2.app/Info.plist
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 2.app/UnCrackable\ Level\ 2
Payload/UnCrackable Level 2.app/UnCrackable Level 2: replacing existing signature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 Payload/UnCrackable\ Level\ 2.app/FridaGadget.dylib
Payload/UnCrackable Level 2.app/FridaGadget.dylib: replacing existing signature
~~~

##### Installing and Running the App


~~~
$ ios-deploy --debug --bundle
~~~

### References

(... TODO - clean this up ...)

http://cydia.saurik.com/package/com.autopear.installipa/
* [1] Dumpdecrypted - https://github.com/stefanesser/dumpdecrypted
* [2] Apple Developer Portal - https://developer.apple.com/
* [3] https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/
