## Setting up a Testing Environment for iOS Apps

In the previous chapter, we provided an overview of the iOS platform and described the structure of iOS apps. In this chapter, we'll introduce basic processes and techniques you can use to test iOS apps for security flaws. These basic processes are the foundation for the test cases outlined in the following chapters.

Unlike the Android emulator, which fully emulates the hardware of an actual Android device, the iOS SDK simulator offers a higher-level *simulation* of an iOS device. Most importantly, emulator binaries are compiled to x86 code instead of ARM code. Apps compiled for a real device don't run, making the simulator useless for black box analysis and reverse engineering.

The following is the most basic iOS app testing setup:

- laptop with admin rights
- Wi-Fi network that permits client-to-client traffic or USB multiplexing
- at least one jailbroken iOS device (of the desired iOS version)
- Burp Suite or other interception proxy tool

Although you can use a Linux or Windows machine for testing, you'll find that many tasks are difficult or impossible on these platforms. In addition, the Xcode development environment and the iOS SDK are only available for macOS. This means that you'll definitely want to work on a Mac for source code analysis and debugging (it also makes black box testing easier).

### Jailbreaking an iOS Device

You should have a jailbroken iPhone or iPad for running tests. These devices allow root access and tool installation, making the security testing process more straightforward. If you don't have access to a jailbroken device, you can apply the workarounds described later in this chapter, but be prepared for a difficult experience.

iOS jailbreaking is often compared to Android rooting, but the process is actually quite different. To explain the difference, we'll first review the concepts of "rooting" and "flashing" on Android.

- **Rooting**: This typically involves installing the `su` binary on the system or replacing the whole system with a rooted custom ROM. Exploits aren't required to obtain root access as long as the bootloader is accessible.
- **Flashing custom ROMs**: This allows you to replace the OS that's running on the device after you unlock the bootloader. The bootloader may require an exploit to unlock it.

On iOS devices, flashing a custom ROM is impossible because the iOS bootloader only allows Apple-signed images to be booted and flashed. This is why even official iOS images can't be installed if they aren't signed by Apple, and it makes iOS downgrades only possible for as long as the previous iOS version is still signed.

The purpose of jailbreaking is to disable iOS protections (Apple's code signing mechanisms in particular) so that arbitrary unsigned code can run on the device. The word "jailbreak" is a colloquial reference to all-in-one tools that automate the disabling process.

Cydia is an alternative app store developed by Jay Freeman (aka "saurik") for jailbroken devices. It provides a graphical user interface and a version of the Advanced Packaging Tool (APT). You can easily access many "unsanctioned" app packages through Cydia. Most jailbreaks install Cydia automatically.

Developing a jailbreak for a given version of iOS is not easy. As a security tester, you'll most likely want to use publicly available jailbreak tools. Still, we recommend studying the techniques that have been used to jailbreak various versions of iOS-you'll encounter many interesting exploits and learn a lot about OS internals. For example, Pangu9 for iOS 9.x [exploited at least five vulnerabilities](https://www.theiphonewiki.com/wiki/Jailbreak_Exploits "Jailbreak Exploits"), including a use-after-free kernel bug (CVE-2015-6794) and an arbitrary file system access vulnerability in the Photos app (CVE-2015-7037).

#### Benefits of Jailbreaking

End users often jailbreak their devices to tweak the iOS system's appearance, add new features, and install third-party apps from unofficial app stores. For a security tester, however, jailbreaking an iOS device has even more benefits. They include, but aren't limited to, the following:
- root access to the file system
- possibility of executing applications that haven't been signed by Apple (which includes many security tools)
- unrestricted debugging and dynamic analysis
- access to the Objective-C runtime

#### Jailbreak Types

There are *tethered*, *semi-tethered*, *semi-untethered*, and *untethered* jailbreaks.

- Tethered jailbreaks don't persist through reboots, so re-applying jailbreaks requires the device to be connected (tethered) to a computer during every reboot. The device may not reboot at all if the computer is not connected.

- Semi-tethered jailbreaks can't be re-applied unless the device is connected to a computer during reboot. The device can also boot into non-jailbroken mode on its own.

- Semi-untethered jailbreaks allow the device to boot on its own, but the kernel patches for disabling code signing aren't applied automatically. The user must re-jailbreak the device by starting an app or visiting a website.

- Untethered jailbreaks are the most popular choice for end users because they need to be applied only once, after which the device will be permanently jailbroken.

#### Caveats and Considerations

Jailbreaking an iOS device is becoming more and more complicated because Apple keeps hardening the system and patching the exploited vulnerabilities. Jailbreaking has become a very time-sensitive procedure because Apple stops signing these vulnerable versions relatively soon after releasing a fix (unless the versions are hardware-based vulnerabilities). This means that you can't downgrade to a specific iOS version once Apple stops signing the firmware.

If you have a jailbroken device that you use for security testing, keep it as is unless you're 100% sure that you can re-jailbreak it after upgrading to the latest iOS version. Consider getting a spare device (which will be updated with every major iOS release) and waiting for a jailbreak to be released publicly. Apple is usually quick to release a patch once a jailbreak has been released publicly, so you have only a couple of days to downgrade to the affected iOS version and apply the jailbreak.

iOS upgrades are based on a challenge-response process. The device will allow the OS installation only if the response to the challenge is signed by Apple. This is what researchers call a "signing window," and it is the reason you can't simply store the OTA firmware package you downloaded via iTunes and load it onto the device whenever you want to. During minor iOS upgrades, two versions may both be signed by Apple. This is the only situation in which you can downgrade the iOS device. You can check the current signing window and download OTA firmware from the [IPSW Downloads website](https://ipsw.me "IPSW Downloads").

#### Which Jailbreaking Tool to Use

Different iOS versions require different jailbreaking techniques. [Determine whether a public jailbreak is available for your version of iOS](https://canijailbreak.com/ "Can I Jailbreak"). Beware of fake tools and spyware, which are often hiding behind domain names that are similar to the name of the jailbreaking group/author.

The jailbreak Pangu 1.3.0 is available for 64-bit devices running iOS 9.0. If you have a device that's running an iOS version for which no jailbreak is available, you can still jailbreak the device if you downgrade or upgrade to the target _jailbreakable_ iOS version (via IPSW download and iTunes). However, this may not be possible if the required iOS version is no longer signed by Apple.

The iOS jailbreak scene evolves so rapidly that providing up-to-date instructions is difficult. However, we can point you to some sources that are currently reliable.

- [Can I Jailbreak?](https://canijailbreak.com/ "Can I Jailbreak?")
- [The iPhone Wiki](https://www.theiphonewiki.com/ "The iPhone Wiki")
- [Redmond Pie](http://www.redmondpie.com/ "Redmone Pie")
- [Reddit Jailbreak](https://www.reddit.com/r/jailbreak/ "Reddit Jailbreak")

> Note that OWASP and the MSTG won't be responsible if you end up bricking your iOS device!

#### Dealing with Jailbreak Detection

Some apps attempt to detect whether the iOS device on which they're running is jailbroken. This is because jailbreaking deactivates some of iOS' default security mechanisms. However, there are several ways to get around this detection, and we'll introduce them in the chapters "Reverse Engineering and Tampering on iOS" and "Testing Anti-Reversing Defenses on iOS."

#### Jailbroken Device Setup

![Cydia Store](Images/Chapters/0x06b/cydia.png)

- *Cydia Store*

Once you've jailbroken your iOS device and Cydia has been installed (as shown in the screenshot above), proceed as follows:

1. From Cydia install aptitude and openssh.
2. SSH into your iOS device.
  - The default users are `root` and `mobile`.
  - The default password is `alpine`.
3. Change the default password for users `root` and `mobile`.
4. Add the following repository to Cydia: `https://build.frida.re`.
5. Install Frida from Cydia.

Cydia allows you to manage repositories. One of the most popular repositories is BigBoss. If your Cydia installation isn't pre-configured with this repository, you can add it by navigating to Sources -> Edit, then clicking "Add" in the top left and entering the following URL:

```
http://apt.thebigboss.org/repofiles/cydia/
```

You may also want to add the HackYouriPhone repository to get the AppSync package:

```
http://repo.hackyouriphone.org
```

The following are some useful packages you can install from Cydia to get started:

- BigBoss Recommended Tools: Installs many useful command line tools for security testing including standard Unix utilities that are missing from iOS, including wget, unrar, less, and sqlite3 client.
- adv-cmds: Advanced command line. Includes finger, fingerd, last, lsvfs, md, and ps.
- [IPA Installer Console](http://cydia.saurik.com/package/com.autopear.installipa/ "IPA Installer Console"): Tool for installing IPA application packages from the command line. Package name is `com.autopear.installipa`.
- Class Dump: A command line tool for examining the Objective-C runtime information stored in Mach-O files.
- Substrate: A platform that makes developing third-party iOS add-ons easier.
- cycript: Cycript is an inlining, optimizing, Cycript-to-JavaScript compiler and immediate-mode console environment that can be injected into running processes.
- AppList: Allows developers to query the list of installed apps and provides a preference pane based on the list.
- PreferenceLoader: A MobileSubstrate-based utility that allows developers to add entries to the Settings application, similar to the SettingsBundles that App Store apps use.
- AppSync Unified: Allows you to sync and install unsigned iOS applications.

Your workstation should have at least the following installed:

- an SSH client
- an interception proxy. In this guide, we'll be using [BURP Suite](https://portswigger.net/burp).

Other useful tools we'll be referring throughout the guide:

- [Introspy](https://github.com/iSECPartners/Introspy-iOS)
- [Frida](http://www.frida.re)
- [IDB](http://www.idbtool.com)
- [Needle](https://github.com/mwrlabs/needle)

### Static Analysis

The preferred method of statically analyzing iOS apps involves using the original Xcode project files. Ideally, you will be able to compile and debug the app to quickly identify any potential issues with the source code.

Black box analysis of iOS apps without access to the original source code requires reverse engineering. For example, no decompilers are available for iOS apps, so a deep inspection requires you to read assembly code. We won't go into too much detail of assembly code in this chapter, but we will revisit the topic in the chapter "Reverse Engineering and Tampering on iOS."

The static analysis instructions in the following chapters are based on the assumption that the source code is available.

#### Automated Static Analysis Tools

Several automated tools for analyzing iOS apps are available; most of them are commercial tools. The free and open source tools [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "Mobile Security Framework (MobSF)") and [Needle](https://github.com/mwrlabs/needle "Needle") have some static and dynamic analysis functionality. Additional tools are listed in the "Static Source Code Analysis" section of the "Testing Tools" appendix.

Don't shy away from using automated scanners for your analysis-they help you pick low-hanging fruit and allow you to focus on the more interesting aspects of analysis, such as the business logic. Keep in mind that static analyzers may produce false positives and false negatives; always review the findings carefully.

### Dynamic Analysis of Jailbroken Devices

Life is easy with a jailbroken device: not only do you gain easy access to the app's sandbox, the lack of code signing allows you to use more powerful dynamic analysis techniques. On iOS, most dynamic analysis tools are based on Cydia Substrate, a framework for developing runtime patches that we will cover later. For basic API monitoring, you can get away with not knowing all the details of how Substrate works-you can simply use existing API monitoring tools.


#### Needle

[Needle](https://github.com/mwrlabs/needle "Needle on GitHub") is an all-in-one iOS security assessment framework. The following section includes the steps necessary to install and use Needle.

##### Installing Needle

**On Linux**

The following commands install the dependencies required to run Needle on Linux.

```
# Unix packages
sudo apt-get install python2.7 python2.7-dev sshpass sqlite3 lib32ncurses5-dev

# Python packages
sudo pip install readline paramiko sshtunnel frida mitmproxy biplist

# Download source
git clone https://github.com/mwrlabs/needle.git

```

**On Mac**

The following commands install the dependencies required to run Needle on macOS.

```
# Core dependencies
brew install python
brew install libxml2
xcode-select --install

# Python packages
sudo -H pip install --upgrade --user readline
sudo -H pip install --upgrade --user paramiko
sudo -H pip install --upgrade --user sshtunnel
sudo -H pip install --upgrade --user frida
sudo -H pip install --upgrade --user biplist
# sshpass
brew install https://raw.githubusercontent.com/kadwanev/bigboybrew/master/Library/Formula/sshpass.rb

# mitmproxy
wget https://github.com/mitmproxy/mitmproxy/releases/download/v0.17.1/mitmproxy-0.17.1-osx.tar.gz
tar -xvzf mitmproxy-0.17.1-osx.tar.gz
sudo cp mitmproxy-0.17.1-osx/mitm* /usr/local/bin/

# Download source
git clone https://github.com/mwrlabs/needle.git
```

##### Install the Needle Agent

The only prerequisite is a Jailbroken device, with the following packages installed:

- `Cydia`
- `Apt 0.7 Strict`

(For nonessential prerequisites, please refer to [Device Dependencies](https://github.com/mwrlabs/needle/wiki/Quick-Start-Guide#device-dependencies)).

- Add the following repository to the Cydia Sources: http://mobiletools.mwrinfosecurity.com/cydia/  
- Search for the NeedleAgent package and install it.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_1.jpg)  ![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_2.jpg)

* If the setup process is successful, you'll find the NeedleAgent app on the home screen.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_3.jpg)

##### Start the Framework

**Start NeedleAgent**

- Open the NeedleAgent app on your device.
- Tap on "Listen" in the top left corner, and the NeedleAgent will start listening on port `4444` by default. The default port can be changed via the field in the top right.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_4.jpg)

**Start Needle**

To launch Needle, just open a console and type:

```
$ python needle.py
      __  _ _______ _______ ______         ______
      | \ | |______ |______ | \     |      |______
      | \_| |______ |______ |_____/ |_____ |______
                  Needle v1.0 [mwr.to/needle]
    [MWR InfoSecurity (@MWRLabs) - Marco Lancini (@LanciniMarco)]

[needle] > help
Commands (type [help|?] <topic>):
---------------------------------
back exit info kill pull reload search shell show use
exec_command help jobs load push resource set shell_local unset

[needle] > show options

  Name                      Current Value                Required  Description
  ------------------------  -------------                --------  -----------
  AGENT_PORT                4444                         yes       Port on which the Needle Agent is listening
  APP                                                    no        Bundle ID of the target application (e.g., com.example.app). Leave empty to launch wizard
  DEBUG                     False                        yes       Enable debugging output
  HIDE_SYSTEM_APPS          False                        yes       If set to True, only 3rd party apps will be shown
  IP                        127.0.0.1                    yes       IP address of the testing device (set to localhost to use USB)
  OUTPUT_FOLDER             /root/.needle/output         yes       Full path of the output folder, where to store the output of the modules
  PASSWORD                  ********                     yes       SSH Password of the testing device
  PORT                      2222                         yes       Port of the SSH agent on the testing device (needs to be != 22 to use USB)
  PUB_KEY_AUTH              True                         yes       Use public key auth to authenticate to the device. Key must be present in the ssh-agent if a passphrase is used
  SAVE_HISTORY              True                         yes       Persists command history across sessions
  SKIP_OUTPUT_FOLDER_CHECK  False                        no        Skip the check that ensures the output folder does not already contain other files. It will automatically overwrite any file
  USERNAME                  root                         yes       SSH Username of the testing device
  VERBOSE                   True                         yes       Enable verbose output

[needle] >
```

You will be presented with Needle's command line interface.

The tool has the following global options (list them via the `show options` command and set them via the `set <option> <value>` command):

- **USERNAME, PASSWORD**: SSH credentials of the testing device (default values are "root" and "alpine", respectively)
- **PUB_KEY_AUTH**: Use public key authentication for the SSH service running on the device. The key must be in the ssh-agent if a passphrase is used.
- **IP, PORT**: The session manager embedded in Needle's core can handle Wi-Fi or USB SSH connections. If SSH-over-USB is chosen, the IP option must be set to localhost ("set IP 127.0.0.1") and PORT must be set to anything other than 22 ("set PORT 2222").
- **AGENT_PORT**: Port on which the installed NeedleAgent is listening.
- **APP**: This is the bundle identifier of the app that will be analyzed (e.g., "com.example.app"). If you don't know it beforehand, you can leave the field empty. Needle will then launch a wizard that prompts the user to select an app.
- **OUTPUT_FOLDER**: This is the full path of the output folder, where Needle will store all module output.
- **SKIP_OUTPUT_FOLDER_CHECK**: If set to "true," the output folder will not be checked for pre-existing files.
- **HIDE_SYSTEM_APPS**: If set to "true," only third-party apps will be shown.
- **SAVE_HISTORY**: If set to "true," the command history will persist across sessions.
- **VERBOSE, DEBUG**: If set to "true," this will enable verbose and debug logging, respectively.


#### SSH Connection via USB

During a real black box test, a reliable Wi-Fi connection may not be available. In this situation, you can use [usbmuxd](https://github.com/libimobiledevice/usbmuxd "usbmuxd") to connect to your device's SSH server via USB.

Usbmuxd is a socket daemon that monitors USB iPhone connections. You can use it to map the mobile device's localhost listening sockets to TCP ports on your host machine. This allows you to conveniently SSH into your iOS device without setting up an actual network connection. When usbmuxd detects an iPhone running in normal mode, it connects to the phone and begins relaying requests that it receives via `/var/run/usbmuxd`.

Connect macOS to an iOS device by installing and starting iproxy:

```bash
$ brew install libimobiledevice
$ iproxy 2222 22
waiting for connection
```

The above command maps port `22` on the iOS device to port `2222` on localhost. With the following command, you should be able to connect to the device:

```shell
$ ssh -p 2222 root@localhost
root@localhost's password:
iPhone:~ root#
```

You can also connect to your iPhone's USB via [Needle](https://labs.mwrinfosecurity.com/blog/needle-how-to/ "Needle").

#### App Folder Structure

System applications are in the `/Applications` directory. You can use [IPA Installer Console](http://cydia.saurik.com/package/com.autopear.installipa "IPA Installer Console") to identify the installation folder for user-installed apps (available under `/private/var/mobile/Containers/` since iOS 9). Connect to the device via SSH and run the command `ipainstaller` (which does the same thing as `installipa`) as follows:

```shell
iPhone:~ root# ipainstaller -l
...
sg.vp.UnCrackable1

iPhone:~ root# ipainstaller -i sg.vp.UnCrackable1
...
Bundle: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1
Application: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1/UnCrackable Level 1.app
Data: /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
```

The user-installed apps have two main subdirectories (plus the `Shared` subdirectory since iOS 9):

- Bundle
- Data

The Application subdirectory, which is inside the Bundle subdirectory, contains the name of the app. The static installer files are in the Application directory, and all user data is in the Data directory.

The random string in the URI is the application's GUID. Every app installation has a unique GUID. There is no relationship between an app's Bundle GUID and its Data GUID.

#### Copying App Data Files

App files are stored in the Data directory. To identify the correct path, SSH into the device and use IPA Installer Console to retrieve the package information (as shown previously):

```bash
iPhone:~ root# ipainstaller -l
...
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

You can now simply archive the Data directory and pull it from the device with `scp`:

```bash
iPhone:~ root# tar czvf /tmp/data.tgz /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
iPhone:~ root# exit
$ scp -P 2222 root@localhost:/tmp/data.tgz .
```

#### Dumping KeyChain Data

[Keychain-Dumper](https://github.com/ptoomey3/Keychain-Dumper/) lets you dump a jailbroken device's KeyChain contents. The easiest way to get the tool is to download the binary from its GitHub repo:

```bash
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

Note that this binary is signed with a self-signed certificate that has a "wildcard" entitlement. The entitlement grants access to *all* items in the Keychain. If you are paranoid or have very sensitive private data on your test device, you may want to build the tool from source and manually sign the appropriate entitlements into your build; instructions for doing this are available in the GitHub repository.

#### Installing Frida

[Frida](https://www.frida.re "Frida") is a runtime instrumentation framework that lets you inject JavaScript snippets or portions of your own library into native Android and iOS apps. If you've already read the Android section of this guide, you should be quite familiar with this tool.

If you haven't already done so, you need to install the Frida Python package on your host machine:

```shell
$ pip install frida
```

To connect Frida to an iOS app, you need a way to inject the Frida runtime into that app. This is easy to do on a jailbroken device: just install `frida-server` through Cydia. Once it has been installed, the Frida server will automatically run with root privileges, allowing you to easily inject code into any process.

Start Cydia and add Frida's repository by navigating to Manage -> Sources -> Edit -> Add and entering https://build.frida.re. You should then be able to find and install the Frida package.

Connect your device via USB and make sure that Frida works by running the `frida-ps` command and the flag '-U'. This should return the list of processes running on the device:

```shell
$ frida-ps -U
PID  Name
---  ----------------
963  Mail
952  Safari
416  BTServer
422  BlueTool
791  CalendarWidget
451  CloudKeychainPro
239  CommCenter
764  ContactsCoreSpot
(...)
```

We`ll demonstrate a few more uses for Frida below.

### Method Tracing with Frida

Intercepting Objective-C methods is a useful iOS security testing technique. For example, you may be interested in data storage operations or network requests. In the following example, we'll write a simple tracer for logging HTTP(S) requests made via iOS standard HTTP APIs. We'll also show you how to inject the tracer into the Safari web browser.

In the following examples, we'll assume that you are working on a jailbroken device. If that's not the case, you first need to follow the steps outlined in the previous section to repackage the Safari app.

Frida comes with `frida-trace`, a ready-made function tracing tool. `frida-trace` accepts Objective-C methods via the "-m" flag. You can pass it wildcards as well-given `-[NSURL *]`, for example, `frida-trace` will automatically install hooks on all `NSURL` class selectors. We'll use this to get a rough idea about which library functions Safari calls when the user opens a URL.

Run Safari on the device and make sure the device is connected via USB. Then start `frida-trace` as follows:

```shell
$ frida-trace -U -m "-[NSURL *]" Safari
Instrumenting functions...                                              
-[NSURL isMusicStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isMusicStoreURL_.js"
-[NSURL isAppStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isAppStoreURL_.js"
(...)
Started tracing 248 functions. Press Ctrl+C to stop.
```

Next, navigate to a new website in Safari. You should see traced function calls on the `frida-trace` console. Note that the `initWithURL:` method is called to initialize a new URL request object.

```shell
           /* TID 0xc07 */
  20313 ms  -[NSURLRequest _initWithCFURLRequest:0x1043bca30 ]
 20313 ms  -[NSURLRequest URL]
(...)
 21324 ms  -[NSURLRequest initWithURL:0x106388b00 ]
 21324 ms     | -[NSURLRequest initWithURL:0x106388b00 cachePolicy:0x0 timeoutInterval:0x106388b80
```

We can look up the declaration of this method on the [Apple Developer Website](https://developer.apple.com/documentation/foundation/nsbundle/1409352-initwithurl?language=objc "Apple Developer Website - initWithURL Instance Method"):

```objective-c
- (instancetype)initWithURL:(NSURL *)url;
```

The method is called with a single argument of type `NSURL`. According to the [documentation](https://developer.apple.com/documentation/foundation/nsurl?language=objc "Apple Developer Website - NSURL class"), the `NSRURL` class has a property called `absoluteString`, whose value should be the absolute URL represented by the `NSURL` object.

We now have all the information we need to write a Frida script that intercepts the `initWithURL:` method and prints the URL passed to the method. The full script is below. Make sure you read the code and inline comments to understand what's going on.


```python
import sys
import frida


// JavaScript to be injected
frida_code = """

	// Obtain a reference to the initWithURL: method of the NSURLRequest class
    var URL = ObjC.classes.NSURLRequest["- initWithURL:];

    // Intercept the method
    Interceptor.attach(URL.implementation, {
      onEnter: function(args) {

      	// We should always initialize an autorelease pool before interacting with Objective-C APIs

        var pool = ObjC.classes.NSAutoreleasePool.alloc().init();

        var NSString = ObjC.classes.NSString;

        // Obtain a reference to the NSLog function, and use it to print the URL value
        // args[2] refers to the first method argument (NSURL *url)

        var NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...']);

        NSLog(args[2].absoluteString_());

        pool.release();
      }
    });
"""

process = frida.get_usb_device().attach("Safari")
script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()
```

Start Safari on the iOS device. Run the above Python script on your connected host and open the device log (we'll explain how to open device logs in the following section). Try opening a new URL in Safari; you should see Frida's output in the logs.

![Frida Xcode Log](Images/Chapters/0x06b/frida-xcode-log.jpg)

Of course, this example illustrates only one of the things you can do with Frida. To unlock the tool's full potential, you should learn to use its [JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript API reference"). The documentation section of the Frida website has a [tutorial](https://www.frida.re/docs/ios/ "Frida Tutorial") and [examples](https://www.frida.re/docs/examples/ios/ "Frida examples") for using Frida on iOS.

### Monitoring Console Logs

Many apps log informative (and potentially sensitive) messages to the console log. The log also contains crash reports and other useful information. You can collect console logs through the Xcode "Devices" window as follows:

1. Launch Xcode.
2. Connect your device to your host computer.
3. Choose Devices from the window menu.
4. Click on your connected iOS device in the left section of the Devices window.
5. Reproduce the problem.
6. Click the triangle-in-a-box toggle located in the lower left-hand corner of the Devices window's right section to view the console log's contents.

To save the console output to a text file, go to the bottom right and click the circular downward-pointing-arrow icon.

![Monitoring console logs through Xcode](Images/Chapters/0x06b/device_console.jpg)

### Setting up a Web Proxy with Burp Suite

Burp Suite is an integrated platform for security testing mobile and web applications. Its tools work together seamlessly to support the entire testing process, from initial mapping and analysis of attack surfaces to finding and exploiting security vulnerabilities. Burp Proxy operates as a web proxy server for Burp Suite, which is positioned as a man-in-the-middle between the browser and web server(s). Burp Suite allows you to intercept, inspect, and modify incoming and outgoing raw HTTP traffic.

Setting up Burp to proxy your traffic is pretty straightforward. We assume that you have an iOS device and workstation connected to a Wi-Fi network that permits client-to-client traffic. If client-to-client traffic is not permitted, you can use usbmuxd to connect to Burp via USB.

Portswigger provides a good [tutorial on setting up an iOS device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp") and a [tutorial on installing Burp's CA certificate to an iOS device ](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device").

#### Bypassing Certificate Pinning

`[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")` is one way to disable certificate pinning. It can be installed via the Cydia store. It will hook on to all high-level API calls and bypass certificate pinning.

The Burp Suite app "[Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Using Burp Suite Mobile Assistant")" can also be used to bypass certificate pinning.

In some cases, certificate pinning is tricky to bypass. Look for the following when you can access the source code and recompile the app:

- the API calls `NSURLSession`, `CFStream`, and `AFNetworking`
- methods/strings containing words like "pinning," "X509," "Certificate," etc.

If you don't have access to the source, you can try binary patching or runtime manipulation:

- If OpenSSL certificate pinning is used, you can try [binary patching](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps").
- Applications written with Apache Cordova or Adobe PhoneGap use a lot of callbacks. Look for the callback function that's called on success and manually call it with Cycript.
- Sometimes, the certificate is a file in the application bundle. Replacing the certificate with Burp's certificate may be sufficient, but beware the certificate's SHA sum. If it's hardcoded into the binary, you must replace it too!

Certificate pinning is a good security practice and should be used for all applications that handle sensitive information. [EFF's Observatory](https://www.eff.org/pl/observatory) lists the root and intermediate CAs that major operating systems automatically trust. Please refer to the [map of the roughly 650 organizations that are Certificate Authorities Mozilla or Microsoft trust (directly or indirectly)](https://www.eff.org/files/colour_map_of_CAs.pdf "Map of the 650-odd organizations that function as Certificate Authorities trusted (directly or indirectly) by Mozilla or Microsoft"). Use certificate pinning if you don't trust at least one of these CAs.

If you want to get more details about white box testing and typical code patterns, refer to "iOS Application Security" by David Thiel. It contains descriptions and code snippets illustrating the most common certificate pinning techniques.

To get more information about testing transport security, please refer to the section "Testing Network Communication."

### Network Monitoring/Sniffing

You can remotely sniff all traffic in real-time on iOS by [creating a Remote Virtual Interface](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819 "Wireshark + OSX + iOS") for your iOS device. First make sure you have Wireshark installed on your macOS machine.

1. Connect your iOS device to your macOS machine via USB.
2. Make sure that your iOS device and your macOS machine are connected to the same network.
3. Open Terminal on macOS and enter the following command: `$ rvictl -s x`, where x is the UDID of your iOS device. You can find the [UDID of your iOS device via iTunes](http://www.iclarified.com/52179/how-to-find-your-iphones-udid "How to Find Your iPhone's UDID").
4. Launch Wireshark and select "rvi0" as the capture interface.
5. Filter the traffic in Wireshark to display what you want to monitor (for example, all HTTP traffic sent/received via the IP address 192.168.1.1).

```shell
ip.addr == 192.168.1.1 && http
```
