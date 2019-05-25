## Android Basic Security Testing

### Basic Android Testing Setup

By now, you should have a basic understanding of the way Android apps are structured and deployed. In this chapter, we'll talk about setting up a security testing environment and describe basic testing processes you'll be using. This chapter is the foundation for the more detailed testing methods discussed in later chapters.

You can set up a fully functioning test environment on almost any machine running Windows, Linux, or Mac OS.

#### Host Device

At the very least, you'll need [Android Studio](https://developer.android.com/studio/index.html "Android Studio") (which comes with the Android SDK) platform tools, an emulator, and an app to manage the various SDK versions and framework components. Android Studio also comes with an Android Virtual Device (AVD) Manager application for creating emulator images. Make sure that the newest [SDK tools](https://developer.android.com/studio/index.html#downloads) and [platform tools](https://developer.android.com/studio/releases/platform-tools.html) packages are installed on your system.


##### Setting up the Android SDK

Local Android SDK installations are managed via Android Studio. Create an empty project in Android Studio and select "Tools->Android->SDK Manager" to open the SDK Manager GUI. The "SDK Platforms" tab is where you install SDKs for multiple API levels. Recent API levels are:

- Android 9.0 (API level 28)
- Android 8.1 (API level 27)
- Android 8.0 (API level 26)
- Android 7.1 (API level 25)

An overview of all Android codenames, their version number and API Levels can be found in the [Android Developer Documentation](https://source.android.com/setup/start/build-numbers "Codenames, Tags, and Build Numbers").

<img src="Images/Chapters/0x05c/sdk_manager.jpg" alt="SDK Manager">

Installed SDKs are on the following paths:

Windows:

```shell
C:\Users\<username>\AppData\Local\Android\sdk
```

MacOS:

```shell
/Users/<username>/Library/Android/sdk
```

Note: On Linux, you need to choose an SDK directory. `/opt`, `/srv`, and `/usr/local` are common choices.

#### Testing Device

##### Testing on a Real Device

For dynamic analysis, you'll need an Android device to run the target app on. In principle, you can do without a real Android device and test on the emulator. However, apps execute quite slowly on the emulator, and this can make security testing tedious. Testing on a real device makes for a smoother process and a more realistic environment.

TODO (e.g. Recommended physical devices: Nexus / Pixel...)

##### Testing on the Emulator

All the above steps for preparing a hardware testing device also apply if an emulator is used. Several tools and VMs that can be used to test an app within an emulator environment are available for dynamic testing:

- MobSF
- Nathan (not updated since 2016)
- AppUse

You can also create an Android Virtual Device with the AVD manager for testing, which is [available within Android Studio](https://developer.android.com/studio/run/managing-avds.html "Create and Manage Virtual Devices")

Please also verify the "Tools" section at the end of this book.

###### Restrictions When Testing on an Emulator

There are several downsides to using an emulator. You may not be able to test an app properly in an emulator if the app relies on a specific mobile network or uses NFC or Bluetooth. Testing within an emulator is also usually slower, and the testing itself may cause issues.

Nevertheless, you can emulate many hardware characteristics, such as [GPS](https://developer.android.com/studio/run/emulator-commandline.html#geo "GPS Emulation") and [SMS](https://developer.android.com/studio/run/emulator-commandline.html#sms "SMS").

##### Getting Privileged Access

*Rooting* (i.e., modifying the OS so that you can run commands as the root user) is recommended for testing on a real device. This gives you full control over the operating system and allows you to bypass restrictions such as app sandboxing. These privileges in turn allow you to use techniques like code injection and function hooking more easily.

Note that rooting is risky, and three main consequences need to be clarified before you proceed. Rooting can have the following negative effects:

- voiding the device warranty (always check the manufacturer's policy before taking any action)
- "bricking" the device, i.e., rendering it inoperable and unusable
- creating additional security risks (because built-in exploit mitigations are often removed)

You should not root a personal device that you store your private information on. We recommend getting a cheap, dedicated test device instead. Many older devices, such as Google's Nexus series, can run the newest Android versions and are perfectly fine for testing.

**You need to understand that rooting your device is ultimately YOUR decision and that OWASP shall in no way be held responsible for any damage. If you're uncertain, seek expert advice before starting the rooting process.**

###### Which Mobiles Can Be Rooted

Virtually any Android mobile can be rooted. Commercial versions of Android OS (which are Linux OS evolutions at the kernel level) are optimized for the mobile world. Some features have been removed or disabled for these versions, for example, non-privileged users' ability to become the 'root' user (who has elevated privileges). Rooting a phone means allowing users to become the root user, e.g., adding a standard Linux executable called `su`, which is used to change to another user account.

To root a mobile device, first unlock its boot loader. The unlocking procedure depends on the device manufacturer. However, for practical reasons, rooting some mobile devices is more popular than rooting others, particularly when it comes to security testing: devices created by Google and manufactured by companies like Samsung, LG, and Motorola are among the most popular, particularly because they are used by many developers. The device warranty is not nullified when the boot loader is unlocked and Google provides many tools to support the root itself. A curated list of guides for rooting all major brand devices is posted on the [XDA forums](https://www.xda-developers.com/root/ "Guide to rooting mobile devices").

###### Rooting with Magisk

Magisk ("Magic Mask") is one way to root your Android device. It's specialty lies in the way, the modifications on the system are performed. While other rooting tools alter the actual data on the system partition, Magisk does not (which is called "systemless"). This enables a way to hide the modifications from root-sensitive applications (e.g. for banking or games) and allows using the official Android OTA upgrades without the need to unroot the device beforehand.

You can get familiar with Magisk reading the official [documentation on GitHub](https://topjohnwu.github.io/Magisk/ "Magisk Documentation"). If you don't have Magisk installed, you can find installation instructions in [the documentation](https://topjohnwu.github.io/Magisk/install.html "Magisk Installation"). If you use an official Android version and plan to upgrade it, Magisk provides a [tutorial on GitHub](https://topjohnwu.github.io/Magisk/tutorials.html#ota-installation "OTA Installation").

Furthermore, developers can use the power of Magisk to create own modules and [submit](https://github.com/Magisk-Modules-Repo/submission "Submission") them to the official [Magisk Modules repository](https://github.com/Magisk-Modules-Repo "Magisk-Modules-Repo"). Submitted modules can then be installed inside the Magisk Manager application. One of these installable modules is a systemless version of the famous [XPosed Framework](https://repo.xposed.info/module/de.robv.android.xposed.installer "Xposed Installer (framework)") (available for SDK versions up to 27).

###### Root Detection

An extensive list of root detection methods is presented in the "Testing Anti-Reversing Defenses on Android" chapter.

For a typical mobile app security build, you'll usually want to test a debug build with root detection disabled. If such a build is not available for testing, you can disable root detection in a variety of ways that will be introduced later in this book.

#### Recommended Tools
TODO recommend a basic set and installation instructions?

##### Frida
TODO We've moved installation and basics from 0x05c to here. Still we have to review this instructions and refer to the official instructions to avoid maintaining them, which does not make sense for us. We should make clear here what's the point on using Frida, what are the benefits for android and some basic commands / features. Also: "Dynamic Instrumentation with Frida" in 0x5c needs a rework.

[Frida](https://www.frida.re "Frida") "lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, Linux, iOS, Android, and QNX." Although it was originally based on Google's V8 JavaScript runtime, Frida has used Duktape since version 9.

Code can be injected in several ways. For example, Xposed permanently modifies the Android app loader, providing hooks for running your own code every time a new process is started.
In contrast, Frida implements code injection by writing code directly into process memory. When attached to a running app, Frida uses ptrace to hijack a thread of a running process. This thread is used to allocate a chunk of memory and populate it with a mini-bootstrapper. The bootstrapper starts a fresh thread, connects to the Frida debugging server that's running on the device, and loads a dynamically generated library file that contains the Frida agent and instrumentation code. The hijacked thread resumes after being restored to its original state, and process execution continues as usual.

Frida injects a complete JavaScript runtime into the process, along with a powerful API that provides a lot of useful functionality, including calling and hooking native functions and injecting structured data into memory. It also supports interaction with the Android Java runtime.

![Frida](Images/Chapters/0x04/frida.png)

*FRIDA Architecture, source: [https://www.frida.re/docs/hacking/](https://www.frida.re/docs/hacking)*

Here are some more APIs FRIDA offers on Android:

- Instantiate Java objects and call static and non-static class methods
- Replace Java method implementations
- Enumerate live instances of specific classes by scanning the Java heap (Dalvik only)
- Scan process memory for occurrences of a string
- Intercept native function calls to run your own code at function entry and exit

The FRIDA Stalker —a code tracing engine based on dynamic recompilation— is available for Android (with support for ARM64), including various enhancements, since Frida version 10.5 ([https://www.frida.re/news/2017/08/25/frida-10-5-released/](https://www.frida.re/news/2017/08/25/frida-10-5-released/)). Some features have limited support on current Android devices, such as support for ART ([https://www.frida.re/docs/android/](https://www.frida.re/docs/android/)), so it is recommended to start out with the Dalvik runtime.

##### Installing Frida

To install Frida locally, simply use PyPI:

```shell
$ sudo pip install frida
```

Your Android device doesn't need to be rooted to run Frida, but it's the easiest setup. We assume a rooted device here unless otherwise noted. Download the frida-server binary from the [Frida releases page](https://github.com/frida/frida/releases). Make sure that you download the right frida-server binary for the architecture of your Android device or emulator: x86, x86_64, arm or arm64. Make sure that the server version (at least the major version number) matches the version of your local Frida installation. PyPI usually installs the latest version of Frida. If you're unsure which version is installed, you can check with the Frida command line tool:

```shell
$ frida --version
9.1.10
$ wget https://github.com/frida/frida/releases/download/9.1.10/frida-server-9.1.10-android-arm.xz
```

Or you can run the following command to automatically detect frida version and download the right frida-server binary:

```shell
$ wget https://github.com/frida/frida/releases/download/$(frida --version)/frida-server-$(frida --version)-android-arm.xz
```

Copy frida-server to the device and run it:

```shell
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "su -c /data/local/tmp/frida-server &"
```

With frida-server running, you should now be able to get a list of running processes with the following command:

```shell
$ frida-ps -U
  PID  Name
-----  --------------------------------------------------------------
  276  adbd
  956  android.process.media
  198  bridgemgrd
 1191  com.android.nfc
 1236  com.android.phone
 5353  com.android.settings
  936  com.android.systemui
(...)
```

The -U option lets Frida search for USB devices or emulators.

To trace specific (low-level) library calls, you can use the `frida-trace` command line tool:

```shell
$ frida-trace -i "open" -U com.android.chrome
```

This generates a little JavaScript in `__handlers__/libc.so/open.js`, which Frida injects into the process. The script traces all calls to the `open` function in `libc.so`. You can modify the generated script according to your needs with Frida [JavaScript API](https://www.frida.re/docs/javascript-api/).

Use `frida CLI` to work with Frida interactively. It hooks into a process and gives you a command line interface to Frida's API.

```shell
$ frida -U com.android.chrome
```

With the `-l` option, you can also use the Frida CLI to load scripts , e.g., to load `myscript.js`:

```shell
$ frida -U -l myscript.js com.android.chrome
```

Frida also provides a Java API, which is especially helpful for dealing with Android apps. It lets you work with Java classes and objects directly. Here is a script to overwrite the `onResume` function of an Activity class:

```java
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function () {
        console.log("[*] onResume() got called!");
        this.onResume();
    };
});
```

The above script calls `Java.perform` to make sure that your code gets executed in the context of the Java VM. It instantiates a wrapper for the `android.app.Activity` class via `Java.use` and overwrites the `onResume()` function. The new `onResume()` function implementation prints a notice to the console and calls the original `onResume()` method by invoking `this.onResume()` every time an activity is resumed in the app.

Frida also lets you search for and work with instantiated objects that are on the heap. The following script searches for instances of `android.view.View` objects and calls their `toString` method. The result is printed to the console:

```java
setImmediate(function() {
    console.log("[*] Starting script");
    Java.perform(function () {
        Java.choose("android.view.View", {
             "onMatch":function(instance){
                  console.log("[*] Instance found: " + instance.toString());
             },
             "onComplete":function() {
                  console.log("[*] Finished heap search")
             }
        });
    });
});
```

The output would look like this:

```shell
[*] Starting script
[*] Instance found: android.view.View{7ccea78 G.ED..... ......ID 0,0-0,0 #7f0c01fc app:id/action_bar_black_background}
[*] Instance found: android.view.View{2809551 V.ED..... ........ 0,1731-0,1731 #7f0c01ff app:id/menu_anchor_stub}
[*] Instance found: android.view.View{be471b6 G.ED..... ......I. 0,0-0,0 #7f0c01f5 app:id/location_bar_verbose_status_separator}
[*] Instance found: android.view.View{3ae0eb7 V.ED..... ........ 0,0-1080,63 #102002f android:id/statusBarBackground}
[*] Finished heap search
```

You can also use Java's reflection capabilities. To list the public methods of the `android.view.View` class, you could create a wrapper for this class in Frida and call `getMethods()` from the wrapper's `class` property:

```java
Java.perform(function () {
    var view = Java.use("android.view.View");
    var methods = view.class.getMethods();
    for(var i = 0; i < methods.length; i++) {
        console.log(methods[i].toString());
    }
});
```

Frida also provides bindings for various languages, including Python, C, NodeJS, and Swift.

##### Objection
TODO

##### Drozer

TODO check if the installation instruction is up-to-date; check if it's just copy and paste. If it is, we just get rid of it and link to the original documentation

[Drozer](https://github.com/mwrlabs/drozer "Drozer on GitHub") is an Android security assessment framework that allows you to search for security vulnerabilities in apps and devices by assuming the role of a third-party app interacting with the other application's IPC endpoints and the underlying OS. The following section documents the steps necessary to install and use Drozer.

###### Installing Drozer

**On Linux:**

Pre-built packages for many Linux distributions are available on the [Drozer website](https://labs.mwrinfosecurity.com/tools/drozer/ "Drozer Website"). If your distribution is not listed, you can build Drozer from source as follows:

```shell
$ git clone https://github.com/mwrlabs/drozer/
$ cd drozer
$ make apks
$ source ENVIRONMENT
$ python setup.py build
$ sudo env "PYTHONPATH=$PYTHONPATH:$(pwd)/src" python setup.py install
```

**On Mac:**

On Mac, Drozer is a bit more difficult to install due to missing dependencies. Mac OS versions from El Capitan onwards don't have OpenSSL installed, so compiling pyOpenSSL won't work. You can resolve this issue by [installing OpenSSL manually]. To install openSSL, run:

```shell
$ brew install openssl
```

Drozer depends on older versions of some libraries. Avoid messing up the system's Python installation by installing Python with homebrew and creating a dedicated environment with virtualenv. (Using a Python version management tool such as [pyenv](https://github.com/pyenv/pyenv "pyenv") is even better, but this is beyond the scope of this book).

Install virtualenv via pip:

```shell
$ pip install virtualenv
```

Create a project directory to work in; you'll download several files into it. Navigate into the newly created directory and run the command `virtualenv drozer`. This creates a "drozer" folder, which contains the Python executable files and a copy of the pip library.

```shell
$ virtualenv drozer
$ source drozer/bin/activate
(drozer) $
```

You're now ready to install the required version of pyOpenSSL and build it against the OpenSSL headers installed previously. A typo in the source of the pyOpenSSL version Drozer prevents successful compilation, so you'll need to fix the source before compiling. Fortunately, ropnop has figured out the necessary steps and documented them in a [blog post](https://blog.ropnop.com/installing-drozer-on-os-x-el-capitan/ "ropnop Blog - Installing Drozer on OS X El Capitan").
Run the following commands:

```shell
$ wget https://pypi.python.org/packages/source/p/pyOpenSSL/pyOpenSSL-0.13.tar.gz
$ tar xzvf pyOpenSSL-0.13.tar.gz
$ cd pyOpenSSL-0.13
$ sed -i '' 's/X509_REVOKED_dup/X509_REVOKED_dupe/' OpenSSL/crypto/crl.c
$ python setup.py build_ext -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
$ python setup.py build
$ python setup.py install
```

With that out of the way, you can install the remaining dependencies.

```shell
$ easy_install protobuf==2.4.1 twisted==10.2.0
```

Finally, download and install the Python .egg from the MWR labs website:

```shell
$ wget https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer-2.3.4.tar.gz
$ tar xzf drozer-2.3.4.tar.gz
$ easy_install drozer-2.3.4-py2.7.egg
```

###### Installing the Agent

Drozer agent is the software component that runs on the device itself. Download the latest Drozer Agent [here](https://github.com/mwrlabs/drozer/releases/) and install it with adb.

```shell
$ adb install drozer.apk
```

###### Starting a Session

You should now have the Drozer console installed on your host machine and the Agent running on your USB-connected device or emulator. Now you need to connect the two to start exploring.

Open the Drozer application in the running emulator and click the OFF button at the bottom of the app to start an Embedded Server.

![alt text](Images/Chapters/0x05b/server.png "Drozer")

The server listens on port 31415 by default. Use adb to forward this port to the localhost interface, then run Drozer on the host to connect to the agent.

```shell
$ adb forward tcp:31415 tcp:31415
$ drozer console connect
```

 Use the "list" command to view all Drozer modules that can be executed in the current session.

###### Basic Drozer Commands

- To list all the packages installed on the emulator, execute the following command:

    `dz> run app.package.list`

- To find the package name of a specific app, pass  "-f" and a search string:

    `dz> run app.package.list –f (string to be searched)`

- To see basic information about the package, execute the following command:

    `dz> run app.package.info –a (package name)`

- To identify the exported application components, execute the following command:

    `dz> run app.package.attacksurface (package name)`

- To identify the list of exported Activities in the target application, execute the following command:

    `dz> run app.activity.info -a (package name)`

- To launch the exported Activities, execute the following command:

    `dz> run app.activity.start --component (package name) (component name)`

- To identify the list of exported Broadcast receivers in the target application, execute the following command:

    `dz> run app.broadcast.info -a (package name)`

- To send a message to a Broadcast receiver, execute the following command:

    `dz> run app.broadcast.send --action (broadcast receiver name) -- extra (number of arguments)`

###### Using Modules

Out of the box, Drozer provides modules for investigating various aspects of the Android platform and a few remote exploits. You can extend Drozer's functionality by downloading and installing additional modules.

###### Finding Modules

The official Drozer module repository is hosted alongside the main project on GitHub. This is automatically set up in your copy of Drozer. You can search for modules with the `module` command:

```shell
dz> module search tool
kernelerror.tools.misc.installcert
metall0id.tools.setup.nmap
mwrlabs.tools.setup.sqlite3
```

For more information about a module, pass the `–d` option to view the module's description:

```shell
dz> module  search url -d
mwrlabs.urls
    Finds URLs with the HTTP or HTTPS schemes by searching the strings
    inside APK files.

        You can, for instance, use this for finding API servers, C&C
    servers within malicious APKs and checking for presence of advertising
    networks.

```

###### Installing Modules

You can install modules with the `module` command:

```shell
dz> module install mwrlabs.tools.setup.sqlite3
Processing mwrlabs.tools.setup.sqlite3... Already Installed.
Successfully installed 1 modules, 0 already installed
```

This will install any module that matches your query. Newly installed modules are dynamically loaded into the console and are available immediately.

### Basic Testing Operations

#### Accessing the Device Shell

##### On-device Shell App
TODO (termux?)

##### Remote Shell

In order to connect to the shell of an Android device, [adb](https://developer.android.com/studio/command-line/adb "Android Debug Bridge") is usually your first tool of choice (unless you've configured remote SSH access).

###### Connecting to an Android Physical Device

When connecting to an Android physical device, you must enable Developer Mode and USB debugging on the device in order to use the ADB debugging interface. Since Android 4.2, the "Developer options" sub menu in the Settings app is hidden by default. To activate it, tap the "Build number" section of the "About phone" view seven times. Note that the build number field's location varies slightly by device—for example, on LG Phones, it is under "About phone -> Software information." Once you have done this, "Developer options" will be shown at bottom of the Settings menu. Once developer options are activated, you can enable debugging with the "USB debugging" switch.

Once USB debugging is enabled, connected devices can be viewed with the following command:

```shell
$ adb devices
List of devices attached
BAZ5ORFARKOZYDFA    device
```

Access to the remote device's shell

```shell
$ adb shell
```

> When you are ready to exit the remote shell, press Control + D or type `exit`.

This will simply work if you have only one device connected. If you have more than one, you'll have to specify the device to which you want to access the shell.

The `adb shell` command can also issue commands to the device without entering the adb remote shell, for example:

```shell
$ adb shell id
```

###### Connecting to an Android Virtual Device

You can either start an Android Virtual Device (AVD) by using the AVD Manager in Android Studio or start the AVD manager from the command line with the `android` command, which is found  in the tools directory of the Android SDK:

```shell
$ ./android avd
```

Once the emulator is up and running, you can establish a root connection with the `adb` command.

```shell
$ adb root
$ adb shell
root@generic_x86:/ $ id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:su:s0
```

Rooting an emulator is therefore unnecessary; root access can be established with `adb`.

#### Host-Device Data Transfer
TODO `adb push pull`, scp. https://developer.android.com/studio/command-line/adb#copyfiles




#### Obtaining and Extracting Apps
##### App Store
TODO mirrorapk or gplaycli

##### Recovering the App Package from the Device
###### From Rooted Devices
TODO via adb pull
###### From Non-Rooted Devices

This works on both rooted and non-rooted devices:

```
$ adb shell pm path sg.vp.owasp_mobile.omtg_android
package:/data/app/sg.vp.owasp_mobile.omtg_android-Q0Y29-poHT2w8912zTxXNw==/base.apk

$ adb pull /data/app/sg.vp.owasp_mobile.omtg_android-Q0Y29-poHT2w8912zTxXNw==/base.apk
/data/app/sg.vp.owasp_mobile.omtg_android-Q0Y29-poHT2w8912zTxXNw==/base.apk: 1 file pulled. 17.9 MB/s (5801767 bytes in 0.309s)
```

#### Installing Apps

Use `adb install` to install an APK on an emulator or connected device.

```bash
adb install path_to_apk
```

Note that if you have the original source code and use Android Studio, you do not need to do this because Android Studio handles the packaging and installation of the app for you.

#### Information Gathering
##### Installed Apps
TODO
```shell
$ adb shell pm list packages
package:com.android.sdm.plugins.connmo
package:com.google.android.googlequicksearchbox
package:com.android.providers.calendar
package:com.android.providers.media
package:com.google.android.onetimeinitializer
package:com.google.android.ext.shared
package:com.android.wallpapercropper
package:sg.vp.owasp_mobile.omtg_android
```



##### App Basic Information
TODO aapt, dumpsys
###### Sandbox

```shell
$ adb shell pm path sg.vp.owasp_mobile.omtg_android
package:/data/app/sg.vp.owasp_mobile.omtg_android-Q0Y29-poHT2w8912zTxXNw==/base.apk
```

```shell
$ adb shell ls /data/data/sg.vp.owasp_mobile.omtg_android
```
###### Permissions
TODO from androidmanifest or aapt dump

```
aapt dump permissions omtg.apk
```
###### Native Libs
TODO APK/libs or from device; or frida / objection when running

```
bullhead:/ # ls /data/data/sg.vp.owasp_mobile.omtg_android/lib
libdatabase_sqlcipher.so libnative.so libsqlcipher_android.so libstlport_shared.so
```

Using objection it is also straightforward as you already land in the sandbox and can directly use `cd` and `ls` commands to look around:

```
$ objection -g sg.vp.owasp_mobile.omtg_android explore

...g.vp.owasp_mobile.omtg_android on (google: 8.1.0) [usb] # ls lib                                                                                                           
Type    Last Modified            Read    Write    Hidden    Size       Name
------  -----------------------  ------  -------  --------  ---------  ------------------------
File    2018-06-06 08:16:34 GMT  True    False    False     13.4 KiB   libnative.so
File    2018-06-06 08:16:34 GMT  True    False    False     181.9 KiB  libdatabase_sqlcipher.so
File    2018-06-06 08:16:34 GMT  True    False    False     357.3 KiB  libstlport_shared.so
File    2018-06-06 08:16:34 GMT  True    False    False     2.2 MiB    libsqlcipher_android.so
```

###### ...


##### Accessing App Data (what to expect, where, sandbox structure)
TODO /data/data
##### Monitoring System Logs
TODO logcat or android studio https://developer.android.com/studio/command-line/logcat.html

```shell
$ adb logcat
```

#### Static Analysis
##### Manual Static Analysis

In Android app security testing, black-box testing (with access to the compiled binary, but not the original source code) is almost equivalent to white-box testing. The majority of apps can be decompiled easily, and having some reverse engineering knowledge and access to bytecode and binary code is almost as good as having the original code unless the release build has been purposefully obfuscated.

For source code testing, you'll need a setup similar to the developer's setup, including a test environment that includes the Android SDK and an IDE. Access to either a physical device or an emulator (for debugging the app) is recommended.

During **black box testing**, you won't have access to the original form of the source code. You'll usually have the application package in [Android's .apk format](https://en.wikipedia.org/wiki/Android_application_package "Android application package"), which can be installed on an Android device or reverse engineered to help you retrieve parts of the source code.

The following pull the APK from the device:

```shell
$ adb shell pm list packages
(...)
package:com.awesomeproject
(...)
$ adb shell pm path com.awesomeproject
package:/data/app/com.awesomeproject-1/base.apk
$ adb pull /data/app/com.awesomeproject-1/base.apk
```

`apkx` provides an easy method of retrieving an APK's source code via the command line. It also packages `dex2jar` and CFR and automates the extraction, conversion, and decompilation steps. Install it as follows:

```shell
$ git clone https://github.com/b-mueller/apkx
$ cd apkx
$ sudo ./install.sh
```

This should copy `apkx` to `/usr/local/bin`. Run it on the APK that you want to test as follows:

```shell
$ apkx UnCrackable-Level1.apk
Extracting UnCrackable-Level1.apk to UnCrackable-Level1
Converting: classes.dex -> classes.jar (dex2jar)
dex2jar UnCrackable-Level1/classes.dex -> UnCrackable-Level1/classes.jar
Decompiling to UnCrackable-Level1/src (cfr)
```

If the application is based solely on Java and doesn't have any native libraries (C/C++ code), the reverse engineering process is relatively easy and recovers almost all the source code. Nevertheless, if the code is obfuscated, this process may be very time-consuming and unproductive. This also applies to applications that contain a native library. They can still be reverse engineered, but the process is not automated and requires knowledge of low-level details.

The "Tampering and Reverse Engineering on Android" section contains more details about reverse engineering Android.

##### Automated Static Analysis

You should use tools for efficient static analysis. They allow the tester to focus on the more complicated business logic. A plethora of static code analyzers are available, ranging from open source scanners to full-blown enterprise-ready scanners. The best tool for the job depends on budget, client requirements, and the tester's preferences.

Some static analyzers rely on the availability of the source code; others take the compiled APK as input.
Keep in mind that static analyzers may not be able to find all problems by themselves even though they can help us focus on potential problems. Review each finding carefully and try to understand what the app is doing to improve your chances of finding vulnerabilities.

Configure the static analyzer properly to reduce the likelihood of false positives. and maybe only select several vulnerability categories in the scan. The results generated by static analyzers can otherwise be overwhelming, and your efforts can be counterproductive if you must manually investigate a large report.

There are several open source tools for automated security analysis of an APK.

- [QARK](https://github.com/linkedin/qark/ "QARK")
- [Androbugs](https://github.com/AndroBugs/AndroBugs_Framework "Androbugs")
- [JAADAS](https://github.com/flankerhqd/JAADAS "JAADAS")

For enterprise tools, see the section "Static Source Code Analysis" in the chapter "Testing Tools."

#### Dynamic Analysis
TODO add intro and basics to dynamic analysis
##### Using Non-Rooted Devices
##### Method Tracing
##### Basic Network Monitoring/Sniffing
TODO maybe move from the next section to here.

### Setting up a Network Testing Environment

#### Basic Network Monitoring/Sniffing

[Remotely sniffing all Android traffic in real-time is possible with tcpdump, netcat (nc), and Wireshark](https://blog.dornea.nu/2015/02/20/android-remote-sniffing-using-tcpdump-nc-and-wireshark/ "Android remote sniffing using Tcpdump, nc and Wireshark"). First, make sure that you have the latest version of [Android tcpdump](https://www.androidtcpdump.com/) on your phone. Here are the [installation steps](https://wladimir-tm4pda.github.io/porting/tcpdump.html "Installing tcpdump"):

```shell
$ adb root
$ adb remount
$ adb push /wherever/you/put/tcpdump /system/xbin/tcpdump
```

If execution of `adb root` returns the  error `adbd cannot run as root in production builds`, install tcpdump as follows:

```shell
$ adb push /wherever/you/put/tcpdump /data/local/tmp/tcpdump
$ adb shell
$ su
$ mount -o rw,remount /system;
$ cp /data/local/tmp/tcpdump /system/xbin/
$ cd /system/xbin
$ chmod 755 tcpdump
```

> Remember: To use tcpdump, you need root privileges on the phone!

Execute `tcpdump` once to see if it works. Once a few packets have come in, you can stop tcpdump by pressing CTRL+c.

```shell
$ tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on wlan0, link-type EN10MB (Ethernet), capture size 262144 bytes
04:54:06.590751 00:9e:1e:10:7f:69 (oui Unknown) > Broadcast, RRCP-0x23 reply
04:54:09.659658 00:9e:1e:10:7f:69 (oui Unknown) > Broadcast, RRCP-0x23 reply
04:54:10.579795 00:9e:1e:10:7f:69 (oui Unknown) > Broadcast, RRCP-0x23 reply
^C
3 packets captured
3 packets received by filter
0 packets dropped by kernel
```

To remotely sniff the Android phone's network traffic, first execute `tcpdump` and pipe its output to `netcat` (nc):

```shell
$ tcpdump -i wlan0 -s0 -w - | nc -l -p 11111
```

The tcpdump command above involves

- listening on the wlan0 interface,
- defining the size (snapshot length) of the capture in bytes to get everything (-s0), and
- writing to a file (-w). Instead of a filename, we pass `-`, which will make tcpdump write to stdout.

By using the pipe (`|`), we sent all output from tcpdump to netcat, which opens a listener on port 11111. You'll usually want to monitor the wlan0 interface. If you need another interface, list the available options with the command `$ ip addr`.

To access port 11111, you need to forward the port to your machine via adb.

```shell
$ adb forward tcp:11111 tcp:11111
```

The following command connects you to the forwarded port via netcat and piping to Wireshark.

```shell
$ nc localhost 11111 | wireshark -k -S -i -
```

Wireshark should start immediately (-k). It gets all data from stdin (-i -) via netcat, which is connected to the forwarded port. You should see all the phone's traffic from the wlan0 interface.

![Wireshark](Images/Chapters/0x05b/Android_Wireshark.png)

You can display the captured traffic in a human-readable format with Wireshark. Figure out which protocols are used and whether they are unencrypted. Capturing all traffic (TCP and UDP) is important, so you should execute all functions of the tested application and analyze it.

<img src="Images/Chapters/0x05b/tcpdump_and_wireshard_on_android.png" alt="Wireshark and tcpdump" width="500">

This neat little trick allows you now to identify what kind of protocols are used and to which endpoints the app is talking to. The questions is now, how can I test the endpoints if Burp is not capable of showing the traffic? There is no easy answer for this, but a few Burp plugins that can get you started.

##### Burp plugins to Process Non-HTTP Traffic

Interception proxies such as Burp and OWASP ZAP won't show non-HTTP traffic, because they aren't capable of decoding it properly by default. There are, however, Burp plugins available such as:

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) and
- [Mitm-relay](https://github.com/jrmdev/mitm_relay).

These plugins can visualize non-HTTP protocols and you will also be able to intercept and manipulate the traffic.

Please note that this setup can become sometimes very tedious and is not as straightforward as testing HTTP.

##### Firebase/Google Cloud Messaging (FCM/GCM)

Firebase Cloud Messaging (FCM), the successor to Google Cloud Messaging (GCM), is a free service offered by Google that allows you to send messages between an application server and client apps. The server and client app communicate via the FCM/GCM connection server, which handles downstream and upstream messages.

![Architectural Overview](Images/Chapters/0x05b/FCM-notifications-overview.png)

Downstream messages (push notifications) are sent from the application server to the client app; upstream messages are sent from the client app to the server.

FCM is available for Android, iOS, and Chrome. FCM currently provides two connection server protocols: HTTP and XMPP. As described in the [official documentation](https://firebase.google.com/docs/cloud-messaging/server#choose "Differences of HTTP and XMPP in FCM"), these protocols are implemented differently. The following example demonstrates how to intercept both protocols.

###### Preparation of Test Setup

You need to either configure iptables on your phone or use bettercap to be able to intercept traffic.

FCM can use either XMPP or HTTP to communicate with the Google backend.

###### HTTP

FCM uses the ports 5228, 5229, and 5230 for HTTP communication. Usually, only port 5228 is used.

- Configure local port forwarding for the ports used by FCM. The following example applies to Mac OS X:

```shell
$ echo "
rdr pass inet proto tcp from any to any port 5228-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5229 -> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5239 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

- The interception proxy must listen to the port specified in the port forwarding rule above (port 8080).

###### XMPP

For XMPP communication, [FCM uses ports](https://firebase.google.com/docs/cloud-messaging/xmpp-server-ref "Firebase via XMPP") 5235 (Production) and 5236 (Testing).

- Configure local port forwarding for the ports used by FCM. The following example applies to Mac OS X:

```shell
$ echo "
rdr pass inet proto tcp from any to any port 5235-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5236 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

###### Intercepting the Requests

The interception proxy must listen to the port specified in the port forwarding rule above (port 8080).

Start the app and trigger a function that uses FCM. You should see HTTP messages in your interception proxy.

![Intercepted Messages](Images/Chapters/0x05b/FCM_Intercept.png)

###### End-to-End Encryption for Push Notifications

As an additional layer of security, push notifications can be encrypted by using [Capillary](https://github.com/google/capillary "Capillary"). Capillary is a library to simplify the sending of end-to-end (E2E) encrypted push messages from Java-based application servers to Android clients.

#### Setting Up an Interception Proxy

Several tools support the network analysis of applications that rely on the HTTP(S) protocol. The most important tools are the so-called interception proxies; OWASP ZAP and Burp Suite Professional are the most famous. An interception proxy gives the tester a man-in-the-middle position. This position is useful for reading and/or modifying all app requests and endpoint responses, which are used for testing Authorization, Session, Management, etc.

##### Interception Proxy for a Virtual Device

###### Setting Up a Web Proxy on an Android Virtual Device (AVD)

The following procedure, which works on the Android emulator that ships with Android Studio 3.x, is for setting up an HTTP proxy on the emulator:

1. Set up your proxy to listen on localhost and for example port 8080.
2. Configure the HTTP proxy in the emulator settings:

    - Click on the three dots in the emulator menu bar
    - Open the Settings Menu
    - Click on the Proxy tab
    - Select "Manual proxy configuration"
    - Enter "127.0.0.1" in the "Host Name" field and your proxy port in the "Port number" field (e.g., "8080")
    - Tap "Apply"

<img width=600px src="Images/Chapters/0x05b/emulator-proxy.png"/>

HTTP and HTTPS requests should now be routed over the proxy on the host machine. If not, try toggling airplane mode off and on.

A proxy for an AVD can also be configured on the command line by using the [emulator command](https://developer.android.com/studio/run/emulator-commandline "Emulator Command") when starting an AVD. The following example starts the AVD Nexus_5X_API_23 and setting a proxy to 127.0.0.1 and port 8080.

```shell
$ emulator @Nexus_5X_API_23 -http-proxy 127.0.0.1:8080
```

###### Installing a CA Certificate on the Virtual Device

An easy way to install a CA certificate is to push the certificate to the device and add it to the certificate store via Security Settings. For example, you can install the PortSwigger (Burp) CA certificate as follows:

1. Start Burp and use a web browser on the host to navigate to burp/, then download `cacert.der` by clicking the "CA Certificate" button.
2. Change the file extension from `.der` to `.cer`.
3. Push the file to the emulator:

    ```shell
    $ adb push cacert.cer /sdcard/
    ```

4. Navigate to "Settings" -> "Security" -> "Install from SD Card."
5. Scroll down and tap `cacert.cer`.

You should then be prompted to confirm installation of the certificate (you'll also be asked to set a device PIN if you haven't already).

For Android 7 and above follow the same procedure described in the "Bypassing the Network Security Configuration" section.

##### Interception Proxy for a Physical Device

The available network setup options must be evaluated first. The mobile device used for testing and the machine running the interception proxy must be connected to the same Wi-Fi network. Use either an (existing) access point or create [an ad-hoc wireless network](https://support.portswigger.net/customer/portal/articles/1841150-Mobile%20Set-up_Ad-hoc%20network_OSX.html "Creating an Ad-hoc Wireless Network in OS X").

Once you've configured the network and established a connection between the testing machine and the mobile device, several steps remain.

- The proxy must be [configured to point to the interception proxy](https://support.portswigger.net/customer/portal/articles/1841101-Mobile%20Set-up_Android%20Device.html "Configuring an Android Device to Work With Burp").
- The [interception proxy's CA certificate must be added to the trusted certificates in the Android device's certificate storage](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp's CA Certificate in an Android Device"). The location of the menu used to store CA certificates may depend on the Android version and Android OEM modifications of the settings menu.
- Some application (e.g. the [Chrome browser](https://bugs.chromium.org/p/chromium/issues/detail?id=475745 "Chromium Issue 475745")) may show `NET::ERR_CERT_VALIDITY_TOO_LONG` errors, if the leaf certificate happens to have a validity extending a certain time (39 months in case of Chrome). This happens if the default Burp CA certificate is used, since the Burp Suite issues leaf certificates with the same validity as its CA certificate. You can circumvent this by creating your own CA certificate and import it to the Burp Suite, as explained in a [blog post on nviso.be](https://blog.nviso.be/2018/01/31/using-a-custom-root-ca-with-burp-for-inspecting-android-n-traffic/ "Using a custom root CA with Burp for inspecting Android N traffic").

After completing these steps and starting the app, the requests should show up in the interception proxy.

> A video of setting up OWASP ZAP with an Android device can be found on [secure.force.com](https://security.secure.force.com/security/tools/webapp/zapandroidsetup "Setting up ZAP for Android").

A few other differences: from Android 8 onward, the network behavior of the app changes when HTTPS traffic is tunneled through another connection. And from Android 9 onward, the SSLSocket and SSLEngine will behave a little bit different in terms of erroring when something goes wrong during the handshakes.

As mentioned before, starting with Android 7, the Android OS will no longer trust user CA certificates by default, unless specified in the application. In the following section, we explain two methods to bypass this Android security control.

###### Bypassing the Network Security Configuration

From Android 7 onwards, the network security configuration allows apps to customize their network security settings, by defining which CA certificates the app will be trusting.

In order to implement the network security configuration for an app, you would need to create a new xml resource file with the name `network_security_config.xml`. This is explained in detail in one of the [Google Android Codelabs](https://codelabs.developers.google.com/codelabs/android-network-security-config/#3 "Basic Network Security Configuration").

After the creation, the apps must also include an entry in the manifest file to point to the new network security configuration file.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>
```

The network security configuration uses an XML file where the app specifies which CA certificates will be trusted. There are various ways to bypass the Network Security Configuration, which will be described below. Please also see the [Security Analyst’s Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/ "Security Analyst’s Guide to Network Security Configuration in Android P") for further information.

####### Adding the User Certificates to the Network Security Configuration

There are different configurations available for the Network Security Configuration to [add non-system Certificate Authorities](https://developer.android.com/training/articles/security-config#CustomTrust "Custom Trust") via the src attribute:

```xml
<certificates src=["system" | "user" | "raw resource"]
              overridePins=["true" | "false"] />


Each certificate can be one of the following:
- a "raw resource" ID pointing to a file containing X.509 certificates
- "system" for the pre-installed system CA certificates
- "user" for user-added CA certificates


The CA certificates trusted by the app can be a system trusted CA as well as a user CA. Usually you will have added the certificate of your interception proxy already as additional CA in Android. Therefore we will focus on the "user" setting, which allows you to force the Android app to trust this certificate with the following Network Security Configuration configuration below:

```xml
<network-security-config>
   <base-config>
      <trust-anchors>
          <certificates src="system" />
          <certificates src="user" />
      </trust-anchors>
   </base-config>
</network-security-config>
```

To implement this new setting you must follow the steps below:

- Decompile the app using a decompilation tool like apktool:

    ```bash
    $ apktool d <filename>.apk
    ```

- Make the application trust user certificates by creating a network security configuration that includes `<certificates src="user" />` as explained above
- Go into the directory created by apktool when decompiling the app and rebuild the app using apktool. The new apk will be in the `dist` directory.

    ```bash
    $ apktool b
    ```

- You need to repackage the app, as explained in the [repackaging chapter](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md#repackaging "Repackaging"). For more details on the repackaging process you can also consult the [Android developer documentation](https://developer.android.com/studio/publish/app-signing#signing-manually), that explains the process as a whole.

Note that even if this method is quite simple its major drawback is that you have to apply this operation for each application you want to evaluate which is additional overhead for testing.

> Bear in mind that if the app you are testing has additional hardening measures, like verification of the app signature you might not be able to start the app anymore. As part of the repackaging you will sign the app with your own key and therefore the signature changes will result in triggering such checks that might lead to immediate termination of the app. You would need to identify and disable such checks either by patching them during repackaging of the app or dynamic instrumentation through Frida.

There is a python script available that automates the steps described above called [Android-CertKiller](https://github.com/51j0/Android-CertKiller "Android-CertKiller"). This Python script can extract the APK from an installed Android app, decompile it, make it debuggable, add a new network security config that allows user certificates, builds and signs the new APK and installs the new APK with the SSL Bypass. The last step, [installing the app might fail](https://github.com/51j0/Android-CertKiller/issues "APK not installing"), due to a bug at the moment.  

```bash
python main.py -w

***************************************
Android CertKiller (v0.1)
***************************************

CertKiller Wizard Mode
---------------------------------
List of devices attached
4200dc72f27bc44d    device

---------------------------------

Enter Application Package Name: nsc.android.mstg.owasp.org.android_nsc

Package: /data/app/nsc.android.mstg.owasp.org.android_nsc-1/base.apk

I. Initiating APK extraction from device
   complete
------------------------------
I. Decompiling
   complete
------------------------------
I. Applying SSL bypass
   complete
------------------------------
I. Building New APK
   complete
------------------------------
I. Signing APK
   complete
------------------------------

Would you like to install the APK on your device(y/N): y
------------------------------------
 Installing Unpinned APK
------------------------------
Finished
```

####### Adding the Proxy's certificate among system trusted CAs using Magisk

In order to avoid the obligation of configuring the Network Security Configuration for each application, we must force the device to accept the proxy's certificate as one of the systems trusted certificates.

There is a [Magisk module](https://github.com/NVISO-BE/MagiskTrustUserCerts "Magisk Trust User Certs") that will automatically add all user-installed CA certificates to the list of system trusted CAs.

Download the latest version of the module [here](https://github.com/NVISO-BE/MagiskTrustUserCerts/releases "Magisk Trust User Certs - Releases"), push the downloaded file over to the device and import it in the Magisk Manager's "Module" view by clicking on the `+` button. Finally, a restart is required by Magisk Manager to let changes take effect.

From now on, any CA certificate that is installed by the user via "Settings", "Security & location", "Encryption & credentials", "Install from storage" (location may differ) is automatically pushed into the system's trust store by this Magisk module. Reboot and verify that the CA certificate is listed in "Settings", "Security & location", "Encryption & credentials", "Trusted credentials" (location may differ).

####### Manually adding the Proxy's certificate among system trusted CAs

Alternatively, you can follow the following steps manually in order to achieve the same result:

- Make the /system partition writable, which is only possible on a rooted device. Run the 'mount' command to make sure the /system is writable: `mount -o rw,remount /system`. If this command fails, try running the following command 'mount -o rw,remount -t ext4 /system'
- Prepare the proxy's CA certificates to match system certificates format. Export the proxy's certificates in `der` format (this is the default format in Burp Suite) then run the following commands:

    ```shell
    $ openssl x509 -inform DER -in cacert.der -out cacert.pem  
    $ openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1  
    mv cacert.pem <hash>.0
    ```

- Finally, copy the `<hash>.0` file into the directory /system/etc/security/cacerts and then run the following command:

    ```shell
    chmod 644 <hash>.0
    ```

By following the steps described above you allow any application to trust the proxy's certificate, which allows you to intercept its traffic, of course unless the application uses SSL pinning.

#### Potential Obstacles

Applications often implement security controls that make it more difficult to perform a security review of the application, such as root detection and certificate pinning. Ideally, you would acquire both a version of the application that has these controls enabled, and one where the controls are disabled. This allows you to analyze the proper implementation of the controls, after which you can continue with the less-secure version for further tests.

Of course, this is not always possible, and you may need to perform a black-box assessment on an application where all security controls are enabled. The section below shows you how you can circumvent certificate pinning for different applications.



##### Client Isolation in Wireless Networks

Once you have setup an interception proxy and have a MITM position you might still not be able to see anything. This might be due to restrictions in the app (see next section) but can also be due to so called client isolation in the Wi-Fi that you are connected to.

[Wireless Client Isolation](https://documentation.meraki.com/MR/Firewall_and_Traffic_Shaping/Wireless_Client_Isolation "Wireless Client Isolation") is a security feature that prevents wireless clients from communicating with one another. This feature is useful for guest and BYOD SSIDs adding a level of security to limit attacks and threats between devices connected to the wireless networks.

What to do if the Wi-Fi we need for testing has client isolation?

You can configure the proxy on your Android device to point to 127.0.0.1:8080, connect your phone via USB to your laptop and use adb to make a reverse port forwarding:

```shell
$ adb reverse tcp:8080 tcp:8080
```

Once you have done this all proxy traffic on your Android phone will be going to port 8080 on 127.0.0.1 and it will be redirected via adb to 127.0.0.1:8080 on your laptop and you will see now the traffic in your Burp. With this trick you are able to test and intercept traffic also in Wi-Fis that have client isolation.

##### Non-Proxy Aware Apps

Once you have setup an interception proxy and have a MITM position you might still not be able to see anything. This is mainly due to the following reasons:

- The app is using a framework like Xamarin that simply is not using the proxy settings of the Android OS or
- The app you are testing is verifying if a proxy is set and is not allowing now any communication.

In both scenarios you would need additional steps to finally being able to see the traffic. In the sections below we are describing two different solutions, bettercap and iptables.

You could also use an access point that is under your control to redirect the traffic, but this would require additional hardware and we focus for now on software solutions.

> For both solutions you need to activate "Support invisible proxying" in Burp, in Proxy Tab/Options/Edit Interface.

###### iptables

You can use iptables on the Android device to redirect all traffic to your interception proxy. The following command would redirect port 80 to your proxy running on port 8080

```shell
$ iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP>:8080
```

Verify the iptables settings and check the IP and port.

```shell
$ iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DNAT       tcp  --  anywhere             anywhere             tcp dpt:5288 to:<Your-Proxy-IP>:8080

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination

Chain natctrl_nat_POSTROUTING (0 references)
target     prot opt source               destination

Chain oem_nat_pre (0 references)
target     prot opt source               destination
```

In case you want to reset the iptables configuration you can flush the rules:

```shell
$ iptables -t nat -F
```

###### bettercap

Read the chapter "Testing Network Communication" and the test case "Simulating a Man-in-the-Middle Attack" for further preparation and instructions for running bettercap.

The machine where you run your proxy and the Android device must be connected to the same wireless network. Start bettercap with the following command, replacing the IP address below (X.X.X.X) with the IP address of your Android device.

```shell
$ sudo bettercap -eval "set arp.spoof.targets X.X.X.X; arp.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;"
bettercap v2.22 (built for darwin amd64 with go1.12.1) [type 'help' for a list of commands]

[19:21:39] [sys.log] [inf] arp.spoof enabling forwarding
[19:21:39] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
```

##### Proxy Detection

Some mobile apps are trying to detect if a proxy is set. If that's the case they will assume that this is malicious and will not work properly.

In order to bypass such a protection mechanism you could either setup bettercap or configure iptables that don't need a proxy setup on your Android phone. A third option we didn't mention before and that is applicable in this scenario is using Frida. It is possible on Android to detect if a system proxy is set by querying the [`ProxyInfo`](https://developer.android.com/reference/android/net/ProxyInfo "ProxyInfo") class and check the getHost() and getPort() methods. There might be various other methods to achieve the same task and you would need to decompile the APK in order to identify the actual class and method name.

Below you can find boiler plate source code for a Frida script that will help you to overload the method (in this case called isProxySet) that is verifying if a proxy is set and will always return false. Even if a proxy is now configured the app will now think that none is set as the function returns false.

```javascript
setTimeout(function(){
    Java.perform(function (){
        console.log("[*] Script loaded")

        var Proxy = Java.use("<package-name>.<class-name>")

        Proxy.isProxySet.overload().implementation = function() {
            console.log("[*] isProxySet function invoked")
            return false
        }
    });
});
```

##### Certificate Pinning

Different ways of implementing certificate pinning have been explained in "Testing Custom Certificate Stores and Certificate Pinning".

If the app implements certificate pinning, X.509 certificates provided by an intercepting proxy will be declined and the app will refuse to make any requests through the proxy. To perform an efficient white box test, use a debug build with deactivated certificate pinning.

There are several ways to bypass certificate pinning for a black box test, depending on the frameworks available on the device:

- Frida: [Objection](https://github.com/sensepost/objection "Objection")
- Xposed: [TrustMeAlready](https://github.com/ViRb3/TrustMeAlready "TrustMeAlready"), [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "SSLUnpinning")
- Cydia Substrate: [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller "Android-SSL-TrustKiller")

For most applications, certificate pinning can be bypassed within seconds, but only if the app uses the API functions that are covered for these tools. If the app is implementing SSL Pinning with a custom framework or library, the SSL Pinning must be manually patched and deactivated, which can be time-consuming.

###### Bypass Custom Certificate Pinning Statically

Somewhere in the application, both the endpoint and the certificate (or its hash) must be defined. After decompiling the application, you can search for:

- Certificate hashes: `grep -ri "sha256\|sha1" ./smali`. Replace the identified hashes with the hash of your proxy's CA. Alternatively, if the hash is accompanied by a domain name, you can try modifying the domain name to a non-existing domain so that the original domain is not pinned. This works well on obfuscated OkHTTP implementations.
- Certificate files: `find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)`. Replace these files with your proxy's certificates, making sure they are in the correct format.

If the application uses native libraries to implement network communication, further reverse engineering is needed. An example of such an approach can be found in the blog post [Identifying the SSL Pinning logic in smali code, patching it, and reassembling the APK](https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/ "Bypassing SSL Pinning in Android Applications")

After making these modifications, repackage the application using apktool and install it on your device.

###### Bypass Custom Certificate Pinning Dynamically

Bypassing the pinning logic dynamically makes it more convenient as there is no need to bypass any integrity checks and it's much faster to perform trial & error attempts.

Finding the correct method to hook is typically the hardest part and can take quite some time depending on the level of obfuscation. As developers typically reuse existing libraries, it is a good approach to search for strings and license files that identify the used library. Once the library has been identified, examine the non-obfuscated source code to find methods which are suited for dynamic instrumentation.

As an example, let's say that you find an application which uses an obfuscated OkHTTP3 library. The [documentation](https://square.github.io/okhttp/3.x/okhttp/ "OkHTTP3 documentation") shows that the CertificatePinner.Builder class is responsible for adding pins for specific domains. If you can modify the arguments to the [Builder.add method](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.Builder.html#add-java.lang.String-java.lang.String...- "Builder.add method"), you can change the hashes to the correct hashes belonging to your certificate. Finding the correct method can be done in either two ways:

- Search for hashes and domain names as explained in the previous section. The actual pinning method will typically be used or defined in close proximity to these strings
- Search for the method signature in the SMALI code

For the Builder.add method, you can find the possible methods by running the following grep command: `grep -ri java/lang/String;\[Ljava/lang/String;)L ./`

This command will search for all methods that take a string and a variable list of strings as arguments, and return a complex object. Depending on the size of the application, this may have one or multiple matches in the code.

Hook each method with Frida and print the arguments. One of them will print out a domain name and a certificate hash, after which you can modify the arguments to circumvent the implemented pinning.



### References

- Signing Manually (Android developer documentation) - <https://developer.android.com/studio/publish/app-signing#signing-manually>
- Custom Trust - <https://developer.android.com/training/articles/security-config#CustomTrust>
- Google Android Codelabs - <https://codelabs.developers.google.com/codelabs/android-network-security-config/#3>
- Security Analyst’s Guide to Network Security Configuration in Android P - <https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/>

#### Tools

- Androbugs - <https://github.com/AndroBugs/AndroBugs_Framework>
- Android-CertKiller - <https://github.com/51j0/Android-CertKiller>
- Android tcpdump - <https://www.androidtcpdump.com/>
- Android-SSL-TrustKiller - <https://github.com/iSECPartners/Android-SSL-TrustKiller>
- Android Platform Tools - <https://developer.android.com/studio/releases/platform-tools.html>
- Android Studio - <https://developer.android.com/studio/index.html>
- Android developer documentation - <https://developer.android.com/studio/publish/app-signing#signing-manually>
- Android 8.0 Behavior Changes - <https://developer.android.com/about/versions/oreo/android-8.0-changes>
- Android 9.0 Behavior Changes - <https://developer.android.com/about/versions/pie/android-9.0-changes-all#device-security-changes>
- apktool - <https://ibotpeaches.github.io/Apktool/>
- apkx - <https://github.com/b-mueller/apkx>
- Burp-non-HTTP-Extension - <https://github.com/summitt/Burp-Non-HTTP-Extension>
- Burp Suite Professional - <https://portswigger.net/burp/>
- Drozer - <https://labs.mwrinfosecurity.com/tools/drozer/>
- Frida - <https://www.frida.re/docs/android/>
- JAADAS - <https://github.com/flankerhqd/JAADAS>
- Magisk Trust User Certs module - <https://github.com/NVISO-BE/MagiskTrustUserCerts/releases>
- Mitm-relay - <https://github.com/jrmdev/mitm_relay>
- Objection - <https://github.com/sensepost/objection>
- OWASP ZAP - <https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project>
- QARK - <https://github.com/linkedin/qark/>
- SDK tools - <https://developer.android.com/studio/index.html#downloads>
- SSLUnpinning - <https://github.com/ac-pm/SSLUnpinning_Xposed>
- Wireshark - <https://www.wireshark.org/>
