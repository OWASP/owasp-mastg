## Basic Security Testing on iOS

### Setting Up Your Testing Environment

#### Jailbreaking iOS

In the iOS world, jailbreaking means disabling Apple's code code signing mechanisms so that apps not signed by Apple can be run. If you're planning to do any form of dynamic security testing on an iOS device, you'll have a much easier time on a jailbroken device, as most useful testing tools are only available outside the app store.

Developing a jailbreak for any given version of iOS is not an easy endeavor. As a security tester, you'll most likely want to use publicly available jailbreak tools (don't worry, we're all script kiddies in some areas). Even so, we recommend studying the techniques used to jailbreak various versions of iOS in the past - you'll encounter many highly interesting exploits and learn a lot about the internals of the OS. For example, Pangu9 for iOS 9.x exploited at least five vulnerabilities, including a use-after-free bug in the kernel (CVE-2015-6794) and an arbitrary file system access vulnerabilty in the Photos app (CVE-2015-7037) [3].

In jailbreak lingo, we talk about tethered and untethered jailbreaking methods. In the "tethered" scenario, the jailbreak doesn't persist throughout reboots, so the device must be connected (tethered) to a computer during every reboot to re-apply it. "Untethered" jailbreaks need only be applied once, making them the most popular choice for end users.

(... TODO: Jailbreaking How-to ...)

### Static Analysis

#### With Source Code

#### Without Source Code

##### Recovering an IPA File From an Installed App

###### From Jailbroken devices

You can use Saurik's IPA Installer to recover IPAs from apps installed on the device. To do this, install IPA installer console [1] via Cydia. Then, ssh into the device and look up the bundle id of the target app. For example:

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

On top of code signing, apps distributed via the app store are also protected using Apple's FairPlay DRM system. This system uses asymmetric cryptography to ensure that any app (including free apps) obtained from the app store only executes on the particular device it is approved to run on. The decryption key is unique to the device and burned into the processor. As of now, the only possible way to obtain the decrypted code from a FairPlay-decrypted app is dumping it from memory while the app is running. On a jailbroken device, this can be done with Stefan Esser's dumpdecrypted tool [2].

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

Unfortunately, thanks to Apple's confusing provisioning and code signing system, this is more challenging to get this right than one would expect: iOS will refuse to run an app unless you get the provisioning profile and code signature header absolutely spot on. This requires you to know about a whole lot of concepts - different types of certificates, BundleIDs, application IDs, team identifiers, and how they are tied together using Apple's build tools. Suffice it to say, getting the OS to run a particular binary that hasn't been built using the default way (XCode) can be an exhilarating process.

The toolset we're going to use consists of optool, Apple's build tools and some shell commands. The method is inspired by the resign script from Vincent Tan's Swizzler project [4]. An alternative way of repackaging using different tools was described by NCC group [3].

To reproduce the steps listed below, download "UnCrackable iOS App Level 1" from the OWASP Mobile Testing Guide repo [5].

##### Getting a Developer Provisioning Profile and Certificate

The *provisioning profile* is a plist file signed by Apple that whitelists your code signing certificate on one or multiple devices. In other words, this is Apple explicitly allowing your app to run in certain contexts, such as debugging on selected devices (development profile). The provisioning profile also includes the *entitlements* granted to your app. The *certificate* contains the private key you'll use to do the actual signing.

In the following section, I'll be using my own signing certificate which is associated with my company's development team. If you have developed and deployed apps iOS using Xcode before, you'll already have a code signing certificate installed. Use the *security* tool to list your existing signing identities:

~~~
$ security find-identity -p codesigning -v
  1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Vantage Point Security Pte. Ltd."
  2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
~~~

If you don't have a signing identity yet, you can create a new one via Xcode [10]. Mercifully, Apple allows you to do this with a regular Apple ID, and will even issue free provisioning profiles for deploying apps on your own devices! 

Once you have generated the signing identity, you'll need to issue a developer provisioning profile that allows you to run the repackaged apps on your device(s). You have two options for doing this:

1. If you are registered as a developer: Use the "regular" way through the Apple Developer Portal to register an App ID and issue the profile [1].

2. With a regular Apple account: Create a signing identity in Xcode and build an empty iOS project. Then, extract embedded.mobileprovision from the app container [3].


This should yield you a file called AwesomeRepackaging.mobileprovision.

Once you have obtained the provisioning profile, you can check its contents with the *security* tool.

~~~
$ security cms -D -i AwesomeRepackaging.mobileprovision 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>For Resigning</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>LRUD9L355Y</string>
	</array>
	<key>CreationDate</key>
	<date>2017-02-10T04:59:18Z</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
	</array>
	<key>DeveloperCertificates</key>
	<array>
		<data>(... CERT DATA ...)</data>
	</array>
	<key>Entitlements</key>
	<dict>
		<key>keychain-access-groups</key>
		<array>
			<string>LRUD9L355Y.*</string>		
		</array>
		<key>get-task-allow</key>
		<true/>
		<key>application-identifier</key>
		<string>LRUD9L355Y.sg.vantagepoint.repackage</string>
		<key>com.apple.developer.team-identifier</key>
		<string>LRUD9L355Y</string>
	</dict>
	<key>ExpirationDate</key>
	<date>2018-02-10T04:59:18Z</date>
	<key>Name</key>
	<string>AwesomeRepackaging</string>
	<key>ProvisionedDevices</key>
	<array>
		<string>3beb97c79f7de8236a3107bca5305bbb25f1b119</string>
	</array>
	<key>TeamIdentifier</key>
	<array>
		<string>LRUD9L355Y</string>
	</array>
	<key>TeamName</key>
	<string>Vantage Point Security Pte. Ltd.</string>
	<key>TimeToLive</key>
	<integer>365</integer>
	<key>UUID</key>
	<string>90b3873f-3160-4d9d-8141-3eea560b876b</string>
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>
~~~

Note that the target device id needs to be listed in the entitlements contained in the profile. Also, the "get-task-allow" key must be set to "true" - this allows other processes, such as the debugging server, to attach to the app process.

##### Other Preparations

Our goal is to make the app load FridaGadget.dylib during startup so we can instrument it using Frida. To achieve this, we'll need to insert an additional load command into the Mach-O header of the main executable. Install otool [3] to automate this process:

~~~
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
~~~

You'll also need FridaGadget.dylib:

~~~
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
~~~


##### Patching, Repackaging and Re-Signing



~~~
$ unzip UnCrackable_Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib" -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
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


Copy the new provisioning profile into the app bundle:

~~~
$ cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
~~~



~~~
$ rm -rf Payload/F/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature

~~~

##### Installing and Running the App

~~~
$ ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
~~~


~~~
$ frida-ps -U
PID  Name
---  ------
499  Gadget
~~~


For troubleshooting see [4].


### References

(... TODO - clean this up ...)

* [1] IPA Installer Console - http://cydia.saurik.com/package/com.autopear.installipa
* [2] Dumpdecrypted - https://github.com/stefanesser/dumpdecrypted
* [3] Optool - https://github.com/alexzielenski/optool
* [4] iOS instrumentation without jailbreak - https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/
* [5] Swizzler 2 - https://github.com/vtky/Swizzler2/wiki
* [6] Uncrackable Level 1 - https://github.com/OWASP/owasp-mstg/tree/master/OMTG-Files/02_Crackmes/02_iOS/UnCrackable_Level1
* [7] Maintaining Certificates - https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingCertificates/MaintainingCertificates.html
* [8] Maintaining Provisioning Profiles - https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingProfiles/MaintainingProfiles.html
* [9] Entitlements Troubleshooting - https://developer.apple.com/library/content/technotes/tn2415/_index.html

