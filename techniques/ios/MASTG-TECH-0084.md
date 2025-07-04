---
title: Debugging
platform: ios
---

Coming from a Linux background you'd expect the `ptrace` system call to be as powerful as you're used to but, for some reason, Apple decided to leave it incomplete. iOS debuggers such as LLDB use it for attaching, stepping or continuing the process but they cannot use it to read or write memory (all `PT_READ_*` and `PT_WRITE*` requests are missing). Instead, they have to obtain a so-called Mach task port (by calling `task_for_pid` with the target process ID) and then use the Mach IPC interface API functions to perform actions such as suspending the target process and reading/writing register states (`thread_get_state`/`thread_set_state`) and virtual memory (`mach_vm_read`/`mach_vm_write`).

> For more information you can refer to the LLVM project in GitHub which contains the [source code for LLDB](https://github.com/llvm/llvm-project/tree/main/lldb "LLDB") as well as Chapter 5 and 13 from "Mac OS X and iOS Internals: To the Apple's Core" [#levin] and Chapter 4 "Tracing and Debugging" from "The Mac Hacker's Handbook" [#miller].

## Debugging with LLDB

The default debugserver executable that Xcode installs can't be used to attach to arbitrary processes (it is usually used only for debugging self-developed apps deployed with Xcode). To enable debugging of third-party apps, the `task_for_pid-allow` entitlement must be added to the debugserver executable so that the debugger process can call `task_for_pid` to obtain the target Mach task port as seen before. An easy way to do this is to add the entitlement to the [debugserver binary shipped with Xcode](https://web.archive.org/web/20190223224236/https://iphonedevwiki.net/index.php/Debugserver "Debug Server on the iPhone Dev Wiki").

To obtain the executable, mount the following DMG image:

```bash
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/<target-iOS-version>/DeveloperDiskImage.dmg
```

You'll find the debugserver executable in the `/usr/bin/` directory on the mounted volume. Copy it to a temporary directory, then create a file called `entitlements.plist` with the following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.springboard.debugapplications</key>
    <true/>
    <key>run-unsigned-code</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
</dict>
</plist>
```

Apply the entitlement with @MASTG-TOOL-0114:

```bash
codesign -s - --entitlements entitlements.plist -f debugserver
```

Copy the modified binary to any directory on the test device. The following examples use usbmuxd to forward a local port through USB.

```bash
iproxy 2222 22
scp -P 2222 debugserver root@localhost:/tmp/
```

Note: On iOS 12 and higher, use the following procedure to sign the debugserver binary obtained from the XCode image.

1) Copy the debugserver binary to the device via scp, for example, in the /tmp folder.

2) Connect to the device via SSH and create the file, named entitlements.xml, with the following content:

   ```xml
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
      <key>platform-application</key>
      <true/>
      <key>com.apple.private.security.no-container</key>
      <true/>
      <key>com.apple.private.skip-library-validation</key>
      <true/>
      <key>com.apple.backboardd.debugapplications</key>
      <true/>
      <key>com.apple.backboardd.launchapplications</key>
      <true/>
      <key>com.apple.diagnosticd.diagnostic</key>
      <true/>
      <key>com.apple.frontboard.debugapplications</key>
      <true/>
      <key>com.apple.frontboard.launchapplications</key>
      <true/>
      <key>com.apple.security.network.client</key>
      <true/>
      <key>com.apple.security.network.server</key>
      <true/>
      <key>com.apple.springboard.debugapplications</key>
      <true/>
      <key>com.apple.system-task-ports</key>
      <true/>
      <key>get-task-allow</key>
      <true/>
      <key>run-unsigned-code</key>
      <true/>
      <key>task_for_pid-allow</key>
      <true/>
   </dict>
   </plist>
   ```

3) Type the following command to sign the debugserver binary using @MASTG-TOOL-0111:

   ```bash
   ldid -Sentitlements.xml debugserver
   ```

4) Verify that the debugserver binary can be executed via the following command:

```bash
./debugserver
```

You can now attach debugserver to any process running on the device.

```bash
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
for armv7.
Attaching to process 2670...
```

With the following command you can launch an application via debugserver running on the target device:

```bash
debugserver -x backboard *:1234 /Applications/MobileSMS.app/MobileSMS
```

Attach to an already running application:

```bash
debugserver *:1234 -a "MobileSMS"
```

You may connect now to the iOS device from your host computer:

```bash
(lldb) process connect connect://<ip-of-ios-device>:1234
```

Typing `image list` gives a list of main executable and all dependent libraries.

## Debugging Release Apps

In the previous section we learned about how to setup a debugging environment on an iOS device using LLDB. In this section we will use this information and learn how to debug a third-party release application. We will continue using the @MASTG-APP-0025 and solve it using a debugger.

In contrast to a debug build, the code compiled for a release build is optimized to achieve maximum performance and minimum binary build size. As a general best practice, most of the debug symbols are stripped for a release build, adding a layer of complexity when reverse engineering and debugging the binaries.

Due to the absence of the debug symbols, symbol names are missing from the backtrace outputs and setting breakpoints by simply using function names is not possible. Fortunately, debuggers also support setting breakpoints directly on memory addresses. Further in this section we will learn how to do so and eventually solve the crackme challenge.

Some groundwork is needed before setting a breakpoint using memory addresses. It requires determining two offsets:

1. Breakpoint offset: The _address offset_ of the code where we want to set a breakpoint. This address is obtained by performing static analysis of the code in a disassembler like Ghidra.
2. ASLR shift offset: The _ASLR shift offset_ for the current process. Since ASLR offset is randomly generated on every new instance of an application, this has to be obtained for every debugging session individually. This is determined using the debugger itself.

> iOS is a modern operating system with multiple techniques implemented to mitigate code execution attacks, one such technique being Address Space Randomization Layout (ASLR). On every new execution of an application, a random ASLR shift offset is generated, and various process' data structures are shifted by this offset.

The final breakpoint address to be used in the debugger is the sum of the above two addresses (Breakpoint offset + ASLR shift offset). This approach assumes that the image base address (discussed shortly) used by the disassembler and iOS is the same, which is true most of the time.

When a binary is opened in a disassembler like Ghidra, it loads a binary by emulating the respective operating system's loader. The address at which the binary is loaded is called _image base address_. All the code and symbols inside this binary can be addressed using a constant address offset from this image base address. In Ghidra, the image base address can be obtained by determining the address of the start of a Mach-O file. In this case, it is 0x100000000.

<img src="Images/Chapters/0x06c/debugging_ghidra_image_base_address.png" width="100%" />

The value of the hidden string is stored in a label with the `hidden` flag set. In the disassembly, the text value of this label is stored in register `X21`, stored via `mov` from `X0`, at offset 0x100004520. This is our _breakpoint offset_.

<img src="Images/Chapters/0x06c/debugging_ghidra_breakpoint.png" width="100%" />

For the second address, we need to determine the _ASLR shift offset_ for a given process. The ASLR offset can be determined by using the LLDB command `image list -o -f`. The output is shown in the screenshot below.

<img src="Images/Chapters/0x06c/debugging_lldb_image_list.png" width="100%" />

In the output, the first column contains the sequence number of the image ([X]), the second column contains the randomly generated ASLR offset, while 3rd column contains the full path of the image and towards the end, content in the bracket shows the image base address after adding ASLR offset to the original image base address (0x100000000 + 0x70000 = 0x100070000). You will notice the image base address of 0x100000000 is same as in Ghidra. Now, to obtain the effective memory address for a code location we only need to add ASLR offset to the address identified in Ghidra. The effective address to set the breakpoint will be 0x100004520 + 0x70000 = 0x100074520. The breakpoint can be set using command `b 0x100074520`.

> In the above output, you may also notice that many of the paths listed as images do not point to the file system on the iOS device. Instead, they point to a certain location on the host computer on which LLDB is running. These images are system libraries for which debug symbols are available on the host computer to aid in application development and debugging (as part of the Xcode iOS SDK). Therefore, you may set breakpoints to these libraries directly by using function names.

After putting the breakpoint and running the app, the execution will be halted once the breakpoint is hit. Now you can access and explore the current state of the process. In this case, you know from the previous static analysis that the register `X0` contains the hidden string, thus let's explore it. In LLDB you can print Objective-C objects using the `po` (_print object_) command.

<img src="Images/Chapters/0x06c/debugging_lldb_breakpoint_solution.png" width="100%" />

Voila, the crackme can be easily solved aided by static analysis and a debugger. There are plethora of features implemented in LLDB, including changing the value of the registers, changing values in the process memory and even [automating tasks using Python scripts](https://lldb.llvm.org/use/python.html "LLDB - Python Scripting").

Officially Apple recommends use of LLDB for debugging purposes, but GDB can be also used on iOS. The techniques discussed above are applicable while debugging using GDB as well, provided the LLDB specific commands are [changed to GDB commands](https://lldb.llvm.org/use/map.html "GDB to LLDB command map").
