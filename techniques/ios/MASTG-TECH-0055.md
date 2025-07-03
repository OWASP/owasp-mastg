---
title: Launching a Repackaged App in Debug Mode
platform: ios
---

If you've repackaged an application with a Frida Gadget, or if you want to attach @MASTG-TOOL-0057 to the application, you have to launch the application in debug mode. When you launch the application via SpringBoard, it will not launch in debug mode and the application will crash.

After the application has been installed using @MASTG-TECH-0056, you can launch it in debug mode using the following commands.

> Note that the commands that are part of @MASTG-TOOL-0126 refer to the latest version available from Github. If you installed them via brew or other package managers, you may have an older version with different command line flags.

## iOS 17 and newer

First, make sure you know the correct Bundle Identifier. Depending on how you signed the application, the actual Bundle Identifier might be different from the original Bundle Identifier. To get an overview of the installed applications, use the `ideviceinstaller` tool (see @MASTG-TOOL-0126):

```bash
$ ideviceinstaller list
CFBundleIdentifier, CFBundleShortVersionString, CFBundleDisplayName
sg.vp.UnCrackable1.QH868V5764, "1.0", "UnCrackable1"
org.owasp.mastestapp.MASTestApp, "3.0.0", "Adyen3DS2Demo"
com.apple.TestFlight, "3.5.2", "TestFlight"
```

In this example, @MASTG-TOOL-0118 appended the team identifier (`QH868V5764`) to the original Bundle Identifier.

Next, we need to get the correct device identifier, which we can get using `idevice_id` (see @MASTG-TOOL-0126):

```bash
$ idevice_id
00008101-1234567890123456 (USB)
00008101-1234567890123456 (Network)
```

Now that we have the correct Bundle Identifier and device ID, we can launch the app using `xcrun` (see @MASTG-TOOL-0072):

```bash
xcrun devicectl device process launch --device 00008101-1234567890123456  --start-stopped sg.vp.UnCrackable1.QH868V5764
13:00:43  Enabling developer disk image services.
13:00:43  Acquired usage assertion.
Launched application with sg.vp.UnCrackable1.QH868V5764 bundle identifier.
```

Finally, you can attach @MASTG-TOOL-0057 using the following commands:

```bash
# Execute the lldb debugger
$ lldb
# Select the iOS device you want to interact with
(lldb) device select 00008101-1234567890123456

# Query the processes on a device.
(lldb) device process list
PID    PARENT USER       TRIPLE                         NAME
====== ====== ========== ============================== ============================
1      0                                                launchd
...
771    0                                                <anonymous>
774    0                                                <anonymous>
781    0                                                ReportCrash
783    0                                                UnCrackable Level 1

# Attach to a specific process by their process ID
(lldb) device process attach --pid 783
Process 783 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x0000000104312920 dyld`_dyld_start
dyld`_dyld_start:
->  0x104312920 <+0>:  mov    x0, sp
    0x104312924 <+4>:  and    sp, x0, #0xfffffffffffffff0
    0x104312928 <+8>:  mov    x29, #0x0 ; =0
    0x10431292c <+12>: mov    x30, #0x0 ; =0
Target 0: (UnCrackable Level 1) stopped.

# Continue execution of all threads in the current process.
(lldb) c
Process 783 resuming
(lldb)
```

More information about debugging iOS apps can be found in @MASTG-TECH-0084.

If you manually injected a Frida Gadget, Frida will now be waiting for you to attach to it. Until you do so, the application will appear frozen.

```bash
$ frida-ps -Ua
PID  Name           Identifier
---  -------------  -------------------------------
389  Calendar       com.apple.mobilecal
783  Gadget         re.frida.Gadget
336  TestFlight     com.apple.TestFlight
783  UnCrackable1   sg.vp.UnCrackable1.QH868V5764
339  Weather        com.apple.weather
```

The `783` process has launched a new thread called Gadget to which you can attach:

```bash
$ frida -U -n Gadget
     ____
    / _  |   Frida 16.5.9 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=00008101-000628803A69001E)

[iPhone::Gadget ]-> ObjC.available
true
```

After attaching, the application will continue executing as normal.

## iOS 16 and older

On older versions of iOS, you can use either `idevicedebug` (see @MASTG-TOOL-0126) or @MASTG-TOOL-0054 to launch the app in debug mode.

### Using idevicedebug

```bash
# Get the package name
$ ideviceinstaller list
CFBundleIdentifier, CFBundleShortVersionString, CFBundleDisplayName
sg.vp.UnCrackable1.QH868V5764, "1.0", "UnCrackable1"
com.apple.TestFlight, "3.7.0", "TestFlight"
com.google.Maps, "24.50.0", "Google Maps"

# Run in debug mode
$ idevicedebug -d run sg.vp.UnCrackable1.QH868V5764
working_directory: /private/var/mobile/Containers/Data/Application/438DE865-2714-4BD9-B1EE-881AD4E54AD1

Setting logging bitmask...
Setting maximum packet size...
Setting working directory...
Setting argv...
app_argv[0] = /private/var/containers/Bundle/Application/E21B5B13-DD85-4C83-9A0E-03FCEBF95CF5/UnCrackable Level 1.app/UnCrackable Level 1
Checking if launch succeeded...
Setting thread...
Continue running process...
```

### Using ios-deploy

To use @MASTG-TOOL-0054, you first have to unzip the IPA file:

```bash
$ unzip Uncrackable1-frida-codesigned.ipa -d unzipped
```

Next, use ios-deploy with the path of the app folder inside of the unzipped IPA:

```bash
$ ios-deploy --bundle 'unzipped/Payload/UnCrackable Level 1.app' -W -d -v
ios-deploy --bundle 'pram/Payload/UnCrackable Level 1.app' -W -d -v
[....] Waiting for iOS device to be connected
Handling device type: 1
Already found device? 0
Hardware Model: D211AP
Device Name: NVISO’s iPhone JBE
Model Name: iPhone 8 Plus
SDK Name: iphoneos
Architecture Name: arm64
Product Version: 16.6.1
Build Version: 20G81
[....] Using 593ad60af30ad045b9cb99d2901031226c1b8c84 (D211AP, iPhone 8 Plus, iphoneos, arm64, 16.6.1, 20G81) a.k.a. '**NVISO**’s iPhone JBE'.
------ Install phase ------
[  0%] Found 593ad60af30ad045b9cb99d2901031226c1b8c84 (D211AP, iPhone 8 Plus, iphoneos, arm64, 16.6.1, 20G81) a.k.a. 'NVISO’s iPhone JBE' connected through USB, beginning install
[  5%] Copying /Users/MAS/unzipped/Payload/UnCrackable Level 1.app/META-INF/ to device
[  5%] Copying /Users/MAS/unzipped/Payload/UnCrackable Level 1.app/META-INF/com.apple.ZipMetadata.plist to device
[  6%] Copying /Users/MAS/unzipped/Payload/UnCrackable Level 1.app/META-INF/com.apple.ZipMetadata.plist to device
...
```

### Attaching Frida

If your application was repackaged with a Frida Gadget, the application will wait for you to attach to it before it continues launching.

In a new terminal window, connect to the Frida gadget, just like in the iOS 17 scenario:

```bash
$ frida-ps -Ua
PID  Name           Identifier
---  -------------  -----------------------------
...
468  Gadget         re.frida.Gadget
...
468  UnCrackable1   sg.vp.UnCrackable1.QH868V5764


$ frida -U -n Gadget
     ____
    / _  |   Frida 16.5.9 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=593ad60af30ad045b9cb99d2901031226c1b8c84)
[iPhone::Gadget ]-> ObjC.available
true
```
