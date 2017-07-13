## Basic Security Testing on iOS

### Foreword on Swift and Objective-C

The vast majority of this chapter is relevant to applications written mainly in Objective-C or having bridged Swift types. Please note that these languages are fundamentally different. Features like method swizzling, which is heavily used by [Cycript](http://www.cycript.org/ "Cycript") will not work with Swift methods. At the time of writing this testing guide, Frida does support [Swift bindings](https://github.com/frida/frida-swift "Frida-swift").

### Setting Up Your Testing Environment

In contrast to the Android emulator, which fully emulates the processor and hardware of an actual Android device, the simulator in the iOS SDK offers a higher-level *simulation* of an iOS device. Most importantly, emulator binaries are compiled to x86 code instead of ARM code. Apps compiled for an actual device don't run, making the simulator completely useless for black-box analysis and reverse engineering.

Ideally you should have a jailbroken iPhone or iPad available for running tests. That way, you get root access to the device and can install a variety of useful tools, making the security testing process more straightforward. If you don't have access to a jailbroken device, you can apply one of the many workarounds described later in this chapter, but be prepared for a less smooth experience.

For your mobile app testing setup you should have at least the following basic setup:

- Laptop with admin rights
- WiFi network with client to client traffic permitted (multiplexing through USB is also possible)
- At least one jailbroken iOS device (with desired iOS version)
- Burp Suite or other interception proxy tool

If you want to get serious with iOS security testing, you need a Mac, for the simple reason that Xcode and the iOS SDK are only available for macOS. Many tasks that you can do effortlessly on Mac are a chore, or even impossible on Windows and Linux. Additionally to the basic setup, the following items are recommended for a sophisticated test setup:

- Macbook with Xcode and Developer Profile
- At least two iOS devices, one jailbroken, second non-jailbroken
- Hopper or IDA Pro

#### Jailbreaking the iOS Device

iOS jailbreaking is often compared to Android rooting. Actually, we have three different things here and it is important to clearly distinguish between them.

On the Android side we have:

- **Rooting**: This typically consists of installing the `su` binary within the existing system or replacing the whole system with an already rooted custom ROM. Normally, exploits are not required in order to obtain root access.
- **Flashing custom ROMs** (that might be already rooted): Allows to completely replace the OS running on the device after unlocking the bootloader (which might require an exploit). There is no such thing on iOS as it is closed-source and _thanks_ to the bootloader that only allows Apple-signed images to be booted and flashed (which is also the reason why downgrades/upgrades with iOS images that are not signed by Apple are not possible).

On iOS side we have:

- **Jailbreaking**: Colloquially, the word "jailbreak" is often used to refer to all-in-one tools that automate the complete jailbreaking process, from executing the exploit(s) to disable system protections (such as Apple's code signing mechanisms) and install the Cydia app store. If you're planning to do any form of dynamic security testing on an iOS device, you'll have a much easier time on a jailbroken device, as most useful testing tools are only available outside the App Store.

Developing a jailbreak for any given version of iOS is not an easy endeavor. As a security tester, you'll most likely want to use publicly available jailbreak tools (don't worry, we're all script kiddies in some areas). Even so, we recommend studying the techniques used to jailbreak various versions of iOS in the past - you'll encounter many highly interesting exploits and learn a lot about the internals of the OS. For example, Pangu9 for iOS 9.x [exploited at least five vulnerabilities](https://www.theiphonewiki.com/wiki/Jailbreak_Exploits "Jailbreak Exploits"), including a use-after-free bug in the kernel (CVE-2015-6794) and an arbitrary file system access vulnerability in the Photos app (CVE-2015-7037).

#### Types of Jailbreaking Methods

In jailbreak lingo, we talk about tethered and untethered jailbreaking methods. In the "tethered" scenario, the jailbreak doesn't persist throughout reboots, so the device must be connected (tethered) to a computer after every reboot to re-apply it. "Untethered" jailbreaks need only be applied once, making them the most popular choice for end users.

#### Benefits of Jailbreaking

A standard user will want to jailbreak in order to tweak the iOS system appearance, add new features or install third party apps from unofficial app stores. However, for a security tester the benefits of jailbreaking an iOS device go far beyond simply tweaking the system. They include but are not limited to the following:

- Removing parts of the security (and other) limitations on the OS imposed by Apple
- Providing root access to the operating system
- Allowing applications and tools not signed by Apple to be installed and run without any restrictions
- Debugging and performing dynamic analysis
- Providing access to the Objective-C Runtime

#### Caveats and Considerations about Jailbreaking

Jailbreaking iOS devices is becoming more and more complicated as Apple keeps hardening the system and patching the corresponding vulnerabilities that jailbreaks are based on. Additionally, it has become a very time sensitive procedure as they stop signing these vulnerable versions within relative short time intervals (unless they are hardware-based vulnerabilities). This means that, contrary to Android, that you can't downgrade to a specific iOS version once Apple is not signing the firmware anymore.

A recommendation here is: if you have a jailbroken device that you use for security testing, keep it as it is, unless you are 100% sure that you can perform another jailbreak to it. Additionally you can think of having a second one, which is updated with every major iOS release and wait for public jailbreak to be released. Once a public jailbreak is released, Apple is quite fast in releasing a patch, hence you have only a couple of days to upgrade to the newest iOS version and jailbreak it (if upgrade is necessary).

The iOS upgrade process is performed online and is based on a challenge-response process. The device will perform the OS installation only if the response to the challenge is signed by Apple. This is what researchers call 'signing window' and explains the fact that you can't simply store the OTA firmware package downloaded via iTunes and load it to the device at any time. During minor iOS upgrades, it is possible that two versions are signed at the same time by Apple. This is the only case when you can downgrade the iOS version. You can check the current signing window and download OTA firmware from the [IPSW Downloads website](https://ipsw.me "IPSW Downloads").


#### How to Jailbreak iOS?

Jailbreaking methods vary across iOS versions. The best choice is to [check if a public jailbreak is available for your iOS version](https://canijailbreak.com/ "Can I Jailbreak"). Beware of fake tools and spyware that is often distributed around the Internet, often hiding behind domain names similar to the jailbreaking group/author.

Let's say you have a device running iOS 9.0, for this version you'll find a jailbreak (Pangu 1.3.0), at least for 64 bit devices. In the case that you have another version for which there's not a jailbreak available, you could still jailbreak it if you downgrade/upgrade to the target _jailbreakable_ iOS version (via IPSW download and iTunes). However, this might not be possible if the required iOS version is not signed anymore by Apple.

The iOS jailbreak scene evolves so rapidly that it is difficult to provide up-to-date instructions. However, we can point you to some, at the time of this writing, reliable sources:

- [The iPhone Wiki](https://www.theiphonewiki.com/ "The iPhone Wiki")
- [Redmond Pie](http://www.redmondpie.com/ "Redmone Pie")
- [Reddit Jailbreak](https://www.reddit.com/r/jailbreak/ "Reddit Jailbreak")

> Note that obviously OWASP and the MSTG will not be responsible if you end up bricking your iOS device!

#### Dealing with Jailbreak Detection

Some apps attempt to detect whether the iOS device they're installed and running on is jailbroken. The reason for this is that jailbreaking deactivates some of iOS' default security mechanisms, leading to a less trustable environment. See also the test cases "Testing Jailbreak Detection" in "Testing Platform Interaction" and "Testing Resiliency Against Reverse Engineering".

The core dilemma with this approach is that, by definition, jailbreaking causes the app's environment to be unreliable: The APIs used to test whether a device is jailbroken can be manipulated, and with code signing disabled, the jailbreak detection code can easily be patched out. It is therefore not a very effective way of impeding reverse engineers. Nevertheless, jailbreak detection can be useful in the context of a larger software protection scheme. We'll revisit this topic in the next chapter.

### Preparing the Test Environment

<img src="Images/Chapters/0x06b/cydia.png" width="500px"/>
- *Cydia Store*

Once you have your iOS device jailbroken and Cydia is installed (as shown in the screenshot above), proceed as following:

1. From Cydia install aptitude and openssh
2. SSH to your iDevice
  * Two users are `root` and `mobile`
  * Default password is `alpine`
3. Change the default password for users root and mobile
4. Add the following repository to Cydia: `https://build.frida.re`
5. Install Frida from Cydia
6. Install following packages with aptitude
```
inetutils
syslogd
less
com.autopear.installipa
class-dump
com.ericasadun.utilities
odcctools
cycript
sqlite3
adv-cmds
bigbosshackertools
```

Your workstation should have a SSH client, Hopper Disassembler, Burp and Frida installed. You can install Frida with pip:

```
$ sudo pip install frida
```

### Static Analysis

#### Manual Static Analysis

<!-- TODO [Add content on security Static Analysis of an iOS app with source code, Objective-C and Swift] -->

#### Automated Static Analysis

Static analysis should be supported through the usage of tools, to make the analysis efficient and to allow the tester to focus on the more complicated business logic. There are a plethora of static code analyzers that can be used, ranging from open source scanners to full blown enterprise ready scanners. The decision on which tool to use depends on the budget, requirements by the client and the preferences of the tester.

Some Static Analyzers rely on the availability of the source code while others take the compiled IPA as input.
It is important to keep in mind that while static analyzers can help us to focus attention on potential problems, they may not be able to find all the problems by itself. Go through each finding carefully and try to understand what the app is doing to improve your chances of finding vulnerabilities.

One important thing to note is to configure the static analyzer properly in order to reduce the likelihood of false positives and maybe only select several vulnerability categories in the scan. The results generated by static analyzers can otherwise be overwhelming and the effort can become counterproductive if an overly large report need to be manually investigated.

Compared to Android there are only a few open source tools that are able to perform security analysis on an IPA or do an automated static analysis. One of the few are:

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "Mobile Security Framework (MobSF)")
- [Needle](https://github.com/mwrlabs/needle "Needle")

See also the section "Static Source Code Analysis" for enterprise tools in the chapter "Testing Tools".

### Dynamic Analysis

#### SSH Connection via USB

[usbmuxd](https://github.com/libimobiledevice/usbmuxd "usbmuxd") is a socket daemon that watches for iPhone connections via USB. You can use it to map listening localhost sockets from the mobile device to TCP ports on your host machine. This conveniently allows you to SSH into your iOS device without any network settings. When it detects an iPhone running in normal mode, it will connect to it and then start relaying requests that it receives via /var/run/usbmuxd.

Connect to an iOS device on macOS by installing and starting iproxy:

```bash
$ brew install libimobiledevice
$ iproxy 2222 22
waiting for connection
```

The command above maps port 22 of the iOS device to port 2222 on localhost. With the following command you should be able to connect to the device:

```
$ ssh -p 2222 root@localhost
root@localhost's password:
iPhone:~ root#
```

There are also other solutions that can be used called gandalf and a python script. Installation and usage is described in detail for both in the [iPhoneWiki](http://iphonedevwiki.net/index.php/SSH_Over_USB "SSH Over USB").

Connecting via USB to your iPhone is also possible by using [Needle](https://labs.mwrinfosecurity.com/blog/needle-how-to/ "Needle").

#### Folder Structure

System applications can be found in the directory "/Applications". For user-installed apps, you can use [IPA Installer Console](http://cydia.saurik.com/package/com.autopear.installipa "IPA Installer Concsole") to identify the appropriate folders of the app.

```
iOS8-jailbreak:~ root# installipa -l
me.scan.qrcodereader
iOS8-jailbreak:~ root# installipa -i me.scan.qrcodereader
Bundle: /private/var/mobile/Containers/Bundle/Application/09D08A0A-0BC5-423C-8CC3-FF9499E0B19C
Application: /private/var/mobile/Containers/Bundle/Application/09D08A0A-0BC5-423C-8CC3-FF9499E0B19C/QR Reader.app
Data: /private/var/mobile/Containers/Data/Application/297EEF1B-9CC5-463C-97F7-FB062C864E56
```

As you can see, there are three main directories:
- `Bundle`,
- `Application` and
- `Data`.

The application directory is a subdirectory of bundle. The static installer files are located in the application directory, whereas all user data resides in the data directory.

The random string in the URI is the application's GUID, which is unique to every installation.

#### Monitoring Console Logs

Many apps log informative (and potentially sensitive) messages to the console log. Besides that, the log also contains crash reports and potentially other useful information. You can collect console logs through the Xcode "Devices" window as follows:

1. Launch Xcode
2. Connect your device to your host computer
3. Choose Devices from the window menu
4. Click on your connected iOS device in the left section of the Devices window
5. Reproduce the problem
6. Click the triangle in a box toggle located in the lower-left corner of the right section of the Devices
window to expose the console log contents

To save the console output to a text file, click the circle with a downward-pointing arrow at the bottom right.

<img src="Images/Chapters/0x06b/device_console.jpg" width="500px"/>
- *Monitoring console logs through Xcode*

#### Setting up a Web Proxy using BurpSuite

Burp Suite is an integrated platform for performing security testing of mobile and web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, to finding and exploiting security vulnerabilities. It is a toolkit where Burp proxy operates as a web proxy server, and sits as a man-in-the-middle between the browser and web server(s). It allows the interception, inspection and modification of the raw HTTP traffic passing in both directions.

Setting up Burp to proxy your traffic through is pretty straightforward. It is assumed that you have both: iOS device and workstation connected to the same WiFi network where client to client traffic is permitted. If client-to-client traffic is not permitted, it is possible to use usbmuxd in order to connect to Burp through USB.

Portswigger also provides a good [tutorial on setting up an iOS Device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp") and a [tutorial on how to install Burps CA certificate in an iOS device ](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device").

#### Certificate Pinning

When you try to intercept the communication between the mobile app and the server, you might fail due to certificate pinning. Certificate pinning is a practice used to tighten the security of the TLS connection. When an application connects to the server using TLS, it checks if the server's certificate is signed with a trusted CA's private key. The verification is based on checking the signature with the public key that is within the device's trusted key store. This in turn contains the public keys of all trusted root CAs.

Certificate pinning means that either the server certificate is bundled within the app binary or the hash of the certificate is hardcoded into the source code and checked when establishing a TLS connection. This would protect against the attack scenario where a CA get's compromised and is issuing a certificate for our domain to a third-party.

Instead of the server certificate also the intermediate certificate of the CA can be used. This has the benefit that the certificate pinning implementation in the app might be valid for 5 to 10 years, instead of changing the server certificate every year and also the need to regularly update the app. For this reason certificate pinning can also become a risk as the server certificate is getting updated mostly on a yearly basis. If a process to update the certificate in the app was not defined and the server certificate is replaced, the whole user base is not able to use the app anymore. An update for the app via App or Play Store also might take a few days. In this case the introduction of a security control can become a risk on it's own for the availability of the service. Besides the technical implementation a business process need to be created that triggers an update for the app once the server certificate will get updated.

A more detailed explanation with a [sample certificate pinning implementation for iOS and Android](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning "Certificate and Public Key Pinning") is provided by OWASP.

##### Bypassing Certificate Pinning

One method to disable certificate pinning is to use `[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")`, which can be installed via Cydia store. It will hook on all high-level API calls and bypass the certificate pinning.

Alternatively Burp Suite offers an app called "[Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Using Burp Suite Mobile Assistant")" that can also be used to bypass certificate pinning.

There are some cases, though, where certificate pinning is more tricky to bypass. Things to look for when you try to bypass certificate pinning and you have access to the source code and are able to recompile the app:

- Look for the following API calls: `NSURLSession`, `CFStream`, `AFNetworking`
- Try to look for methods/strings containing words like 'pinning', 'X509', 'Certificate', etc.

If you do not have access to the source you can try binary patching or runtime manipulation:

- In case OpenSSL certificate pinning is implemented you can try [binary patching](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps").
- Applications written by using Apache Cordova or Adobe Phonegap heavily use callbacks. You can look for the callback function called upon success and call it manually with Cycript.
- Sometimes the certificate resides as a file within the application bundle. It might be sufficient to replace it with Burp's certificate, but beware of the certificate's SHA sum that might be hardcoded in the binary. In that case you must replace it too!

Certificate pinning is a good security practice and should be used for all applications handling sensitive information. [EFF's Observatory](https://www.eff.org/pl/observatory) provides list of root and intermediate CAs that are by default trusted on major operating systems. Please also refer to a [map of the 650-odd organizations that function as Certificate Authorities trusted (directly or indirectly) by Mozilla or Microsoft](https://www.eff.org/files/colour_map_of_CAs.pdf "Map of the 650-odd organizations that function as Certificate Authorities trusted (directly or indirectly) by Mozilla or Microsoft"). Use certificate pinning if you don't trust at least one of these CAs.

If you want to get more details on white-box testing and usual code patters, refer to "iOS Application Security" by David Thiel. It contains description and code snippets of most-common techniques used to perform certificate pinning.

To get more information on testing transport security, please refer to section "Testing Network Communication".

#### Dynamic Analysis On Jailbroken Devices

Life is easy with a jailbroken device: Not only do you gain easy access to the app's sandbox, you can also use more powerful dynamic analysis techniques due to the lack of code singing. On iOS, most dynamic analysis tools are built on top of Cydia Substrate, a framework for developing runtime patches that we will cover in more detail in the "Tampering and Reverse Engineering" chapter. For basic API monitoring purposes however, you can get away without knowing Substrate in detail - you can simply use existing tools built for this purpose.

##### Copying App Data Files

Files belonging to an app are stored in the app's data directory. To identify the correct path, ssh into the device and retrieve the package information using IPA Installer Console:

```bash
iPhone:~ root# ipainstaller -l
sg.vp.UnCrackable-2
sg.vp.UnCrackable1

iPhone:~ root# ipainstaller -i sg.vp.UnCrackable1
Identifier: sg.vp.UnCrackable1
Version: 1
Short Version: 1.0
Name: UnCrackable1
Display Name: UnCrackable Level 1
Bundle: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1
Application: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1/UnCrackable Level 1.app
Data: /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
```

You can now simply archive the data directory and pull it from the device using scp.

```bash
iPhone:~ root# tar czvf /tmp/data.tgz /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
iPhone:~ root# exit
$ scp -P 2222 root@localhost:/tmp/data.tgz .
```

##### Dumping KeyChain Data

[Keychain-Dumper](https://github.com/ptoomey3/Keychain-Dumper/) lets you dump the contents of the KeyChain on a jailbroken device. The easiest way of running the tool is to download the binary from its GitHub repo:

``` bash
$ git clone https://github.com/ptoomey3/Keychain-Dumper
$ scp -P 2222 Keychain-Dumper/keychain_dumper root@localhost:/tmp/
$ ssh -p 2222 root@localhost
iPhone:~ root# chmod +x /tmp/keychain_dumper
iPhone:~ root# /tmp/keychain_dumper

(...)

Generic Password
----------------
Service: myApp
Account: key3
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: SmJSWxEs

Generic Password
----------------
Service: myApp
Account: key7
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: WOg1DfuH
```

Note however that this binary is signed with a self-signed certificate with a "wildcard" entitlement, granting access to *all* items in the Keychain - if you are paranoid, or have highly sensitive private data on your test device, you might want to build the tool from source and manually sign the appropriate entitlements into your build - instructions for doing this are available in the GitHub repository.

<!--

##### Security Profiling with Introspy

Intospy is an open-source security profiler for iOS released by iSecPartners. Built on top of substrate, it can be used to log security-sensitive API calls on a jailbroken device.  The recorded API calls sent to the console and written to a database file, which can then be converted into an HTML report using Introspy-Analyzer <code>[32]</code>.

-->

<!-- TODO [Write an IntroSpy howto] -->

#### Dynamic Analysis on Non-Jailbroken Devices

If you don't have access to a jailbroken device, you can patch and repackage the target app to load a dynamic library at startup. This way, you can instrument the app and can do pretty much everything you need for a dynamical analysis (of course, you can't break out of the sandbox that way, but you usually don't need to). This technique however works only on if the app binary isn't FairPlay-encrypted (i.e. obtained from the app store).

Thanks to Apple's confusing provisioning and code signing system, re-signing an app is more challenging than one would expect. iOS refuses to run an app unless you get the provisioning profile and code signature header absolutely right. This requires you to learn about a whole lot of concepts - different types of certificates, BundleIDs, application IDs, team identifiers, and how they are tied together using Apple's build tools. Suffice it to say, getting the OS to run a particular binary that hasn't been built using the default way (Xcode) can be a daunting process.

The toolset we're going to use consists of `optool`, Apple's build tools and some shell commands. Our method is inspired by [Vincent Tan's Swizzler project](https://github.com/vtky/Swizzler2/ "Swizzler"). An alternative way of repackaging using different tools was [described by NCC group](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "NCC blog - iOS instrumentation without jailbreak").

To reproduce the steps listed below, download [UnCrackable iOS App Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/iOS/Level_01 "Crackmes - iOS Level 1") from the OWASP Mobile Testing Guide repo. Our goal is to make the UnCrackable app load FridaGadget.dylib during startup so we can instrument it using Frida.

> Please note that all of the following steps are applicable for macOS only. Also Xcode is only available for macOS.

##### Getting a Developer Provisioning Profile and Certificate

The *provisioning profile* is a plist file signed by Apple that whitelists your code signing certificate on one or multiple devices. In other words, this is Apple explicitly allowing your app to run in certain contexts, such as debugging on selected devices (development profile). The provisioning profile also includes the *entitlements* granted to your app. The *certificate* contains the private key you'll use to do the actual signing.

Depending on whether you're registered as an iOS developer, you can use one of the following two ways to obtain a certificate and provisioning profile.

**With an iOS developer account:**

If you have developed and deployed iOS apps using Xcode before, you'll already have your own code signing certificate installed. Use the *security* tool to list your existing signing identities:

```
$ security find-identity -p codesigning -v
  1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Vantage Point Security Pte. Ltd."
  2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
```

Log into the Apple Developer portal to issue a new App ID, then issue and download the profile. The App ID can be anything - you can use the same App ID for re-signing multiple apps. Make sure you create a *development* profile and not a *distribution* profile, as you'll want to be able to debug the app.

In the examples below I'm using my own signing identity which is associated with my company's development team. I created the app-id "sg.vp.repackaged", as well as a provisioning profile aptly named "AwesomeRepackaging" for this purpose, and ended up with the file AwesomeRepackaging.mobileprovision - exchange this with your own filename in the shell commands below.

**With a regular iTunes account:**

Mercifully, Apple will issue a free development provisioning profile even if you're not a paying developer. You can obtain the profile with Xcode using your regular Apple account - simply build an empty iOS project and extract embedded.mobileprovision from the app container, which is located in the Xcode directory in your home directory `~/Library/Developer/Xcode/DerivedData/<ProjectName>/Build/Products/Debug-iphoneos/<ProjectName>.app/`. The [NCC blog post "iOS instrumentation without jailbreak"](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "iOS instrumentation without jailbreak") explains this process in great detail.

Once you have obtained the provisioning profile, you can check its contents with the *security* tool. Besides the allowed certificates and devices, you'll find the entitlements granted to the app in the profile. You'll need those later for code signing, so extract them to a separate plist file as shown below. It is also worth having a look at the contents of the file to check if everything looks as expected.

```
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
```

Note the application identifier, which is a combination of the Team ID (LRUD9L355Y) and Bundle ID (sg.vantagepoint.repackage). This provisioning profile is only valid for the one app with this particular app id. The "get-task-allow" key is also important - when set to "true", other processes, such as the debugging server, are allowed to attach to the app (consequently, this would be set to "false" in a distribution profile).

##### Other Preparations

To make our app load an additional library at startup we need some way of inserting an additional load command into the Mach-O header of the main executable. [Optool](https://github.com/alexzielenski/optool "Optool") can be used to automate this process:

```
$ git clone https://github.com/alexzielenski/optool.git
$ cd optool/
$ git submodule update --init --recursive
$ xcodebuild
$ ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

We'll also use [ios-deploy](https://github.com/phonegap/ios-deploy "ios-deploy"), a tool that enables deploying and debugging of iOS apps without using Xcode:

```
$ git clone https://github.com/phonegap/ios-deploy.git
$ cd ios-deploy/
$ xcodebuild
$ cd build/Release
$ ./ios-deploy
$ ln -s <your-path-to-ios-deploy>/build/Release/ios-deploy /usr/local/bin/ios-deploy
```

The last line in optool and ios-deploy creates a symbolic link and makes the executable available system-wide.

To follow the examples below, you also need FridaGadget.dylib:

```
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
```

Besides the tools listed above, we'll be using standard tools that come with macOS and Xcode and make sure you have the [Xcode command line developer tools](http://railsapps.github.io/xcode-command-line-tools.html "Xcode Command Line Tools") installed.

##### Patching, Repackaging and Re-Signing

Time to get serious! As you already now, IPA files are actually ZIP archives, so use any zip tool to unpack the archive. Then, copy FridaGadget.dylib into the app directory, and add a load command to the "UnCrackable Level 1" binary using optool.

```
$ unzip UnCrackable_Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

Such blatant tampering of course invalidates the code signature of the main executable, so this won't run on a non-jailbroken device. You'll need to replace the provisioning profile and sign both the main executable and FridaGadget.dylib with the certificate listed in the profile.

First, let's add our own provisioning profile to the package:

```
$ cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
```

Next, we need to make sure that the BundleID in Info.plist matches the one specified in the profile. The reason for this is that the "codesign" tool will read the Bundle ID from Info.plist during signing - a wrong value will lead to an invalid signature.

```
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
```

Finally, we use the codesign tool to re-sign both binaries. You need to use your signing identity instead of the value "8004380F331DCA22CC1B47FB1A805890AE41C938" which you can get by executing the command `security find-identity -p codesigning -v`.

```
$ rm -rf Payload/F/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
```

The entitlements.plist is the file you created earlier in your empty iOS project.

```
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature
```

##### Installing and Running the App

Now you should be all set for running the modified app. Deploy and run the app on the device as follows.

```
$ ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
```

If everything went well, the app should launch on the device in debugging mode with lldb attached. Frida should now be able to attach to the app as well. You can verify this with the frida-ps command:

```
$ frida-ps -U
PID  Name
---  ------
499  Gadget
```

![Frida on non-JB device](Images/Chapters/0x06b/fridaStockiOS.png "Frida on non-JB device")

##### Troubleshooting.

If something goes wrong (which it usually does), mismatches between the provisioning profile and code signing header are the most likely suspect. In that case it is helpful to read the [official documentation](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingProfiles/MaintainingProfiles.html "Maintaining Provisioning Profiles") and gaining a deeper understanding of the code signing process. I also found Apple's [entitlement troubleshooting page](https://developer.apple.com/library/content/technotes/tn2415/_index.html "Entitlements Troubleshooting ") to be a useful resource.


##### Network Monitoring/Sniffing

Dynamic analysis by using an interception proxy can be straight forward if standard libraries in iOS are used and all communication is done via HTTP. But what if XMPP or other protocols are used that are not recognized by your interception proxy? What if mobile application development platforms like Xamarin are used, where the produced apps do not use the local proxy settings of your iOS device? In this case we need to monitor and analyze the network traffic first in order to decide what to do next.

On iOS it is possible to remotely sniff all traffic in real-time by using Wireshark and [creating a Remote Virtual Interface](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819 "Wireshark + OSX + iOS") for your iOS device. First ensure you have Wireshark installed on your macOS workstation.

1. Connect your iOS device to your macOS workstation via a USB cable.
2. Ensure that both your iOS device and your macOS workstation are connected to the same network.
3. Open up "Terminal" on your macOS and enter the following command: `$ rvictl -s x`, where x is the UDID of your iOS device.  You can find the UDID of your iOS device via iTunes.
4. Launch Wireshark and select "rvi0" as the capture interface.
5. Filter the traffic accordingly in Wireshark to display what you want to monitor, for example `ip.addr == 192.168.1.1 && http`.
