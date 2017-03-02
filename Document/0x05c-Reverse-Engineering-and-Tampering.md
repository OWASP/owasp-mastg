## Tampering and Reverse Engineering on Android

Its openness makes Android a favorable environment for reverse engineers. However, dealing with both Java and native code can make things more complicated at times. In the following chapter, we'll look at some peculiarities of Android reversing and OS-specific tools as processes.

In comparison to iOS, Android offers some big advantages to reverse engineers. First of all transparency: You can study the source code of the Android Open Source Project (AOSP), build your ROMs, and so on. The OS is also much more friendly to developers and tinkerers in other way: From the developer options available by default, to the way debugging is set up and the tools shipping with the SDK, there's lot of niceties to make your life easier compared to "some other vendors".

However, there's also a few challenges you'll encounter. For example, if you're used to analyzing native code, you'll need to SMALI to your repertoire. As it is easy for developers to call into native code via the Java Native Interface (JNI), you'll often need to work with Java and native code at the same time. JNI is sometimes used on purpose to confuse reverse engineers (to be fair, there might also be legitimate reasons for using JNI, such as improving performance or supporting legacy code). Developers seeking to impede reverse engineering deliberately split functionality between Java bytecode and native code, structuring their apps such that execution frequently jumps between the two layers.

You'll need a working knowledge about both the Java-based Android environment and the Linux OS and Kernel that forms the basis of Android (better yet, they’d know all these components inside out). Plus, they need the right toolset to deal with both native code and bytecode running inside the Java virtual machine.

### Environment and Toolset

At the very minimum, you'll need the Android SDK [1]. The SDK contains basic utilities for dealing with Android Apps and ELF binaries, the Android Debugging Bridge (ADB) client, and tools to help with tracing and debugging. In addition to the SDK, you'll also need a basic disassembler - APKTool [1] is the most popular free tool to do, plus you can use it to modify and re-assemble apps. It can extract and disassemble resources directly from the APK archive and disassemble Java bytecode to SMALI. It also allows you to reassemble the APK package, which is useful for patching and applying changes to the Manifest.

Other than that, it's really a matter of preference and budget. A ton of free and commercial disassemblers, decompilers, and frameworks with different strengths and weaknesses exist - we'll cover some of them below.

#### Building a Reverse Engineering Environment For Free

With a little effort you can build a reasonable GUI-based reverse engineering environment for free. JD [2] is a free Java de-compiler that integrates with Eclipse [3] and IntelliJ IDEA [4]. Generally, IntelliJ is the more light-weight solution and works great for browsing the source code and also allows for basic on-device debugging of the decompiled apps. However, if you prefer something that's clunky, slow and complicated to use, Eclipse is the right IDE for you (note: Author's opinion).

If you don’t mind looking at SMALI instead of Java code, you can use the smalidea plugin for IntelliJ for debugging on the device [5]. Smalidea supports single-stepping through the bytecode, identifier renaming and watches for non-named registers, which makes it much more powerful than a JD + IntelliJ setup.

More elaborate tasks such as program analysis and automated de-obfuscation can be achieved with open source reverse engineering frameworks such as Radare2 [6] and Angr[7]. You'll find examples usages for many of these free tools and frameworks throughout the guide.

#### Commercial Tools

###### JEB

JEB [8], a commercial decompiler, packs all the functionality needed for static and dynamic analysis of Android apps into a convenient all-in-one package, is reasonably reliable and you get quick support. It has a built-in debugger, which allows for an efficient workflow – setting breakpoints directly in the decompiled (and annotated sources) is invaluable, especially when dealing with ProGuard-obfuscated bytecode. Of course convenience like this doesn’t come cheap - at $90 / month for the standard license, JEB isn’t exactly a steal.

###### IDA Pro

IDA Pro [9] understands ARM, MIPS and of course Intel ELF binaries, plus it can deal with Java bytecode. It also comes with remote debuggers for both Java applications and native processes. With its capable disassembler and powerful scripting and extension capabilities, IDA Pro works great for static analysis of native programs and libraries. However, the static analysis facilities it offers for Java code are somewhat basic – you get the SMALI disassembly but not much more. There’s no navigating the package and class structure, and some things (such as renaming classes) can’t be done which can make working with more complex Java apps a bit tedious.

##### Emulation/Introspection-Based

###### DroidScope

DroidScope [10] - an extension to the DECAF dynamic analysis framework [11] - is a malware analysis engine based on QEMU. It adds instrumentation on several levels, making it possible to fully reconstruct the semantics on the hardware, Linux and Java level.

DroidScope exports instrumentation APIs that mirror the different context levels (hardware, OS and Java) of a real Android device. Analysis tools can use these APIs to query or set information and register callbacks for various events. For example, a plugin can register callbacks for native instruction start and end, memory reads and writes, register reads and writes, system calls or Java method calls.

All of this makes it possible to build tracers that are practically transparent to the target application (as long as we can hide the fact it is running in an emulator). One limitation is that DroidScope is compatible with the Dalvik VM only.

###### PANDA

PANDA [12] is another QEMU-based dynamic analysis platform. Similar to DroidScope, PANDA can be extended by registering callbacks that are triggered upon certain QEMU events. The twist PANDA adds is its record/replay feature. This allows for an iterative workflow: The reverse engineer records an execution trace of some the target app (or some part of it) and then replays it over and over again, refining his analysis plugins with each iteration.

PANDA comes with some pre-made plugins, such as a stringsearch tool and a syscall tracer. Most importantly, it also supports Android guests and some of the DroidScope code has even been ported over. Building and running PANDA for Android (“PANDROID”) is relatively straightforward. To test it, clone Moiyx’s git repository and build PANDA as follows:

~~~
$ cd qemu
$ ./configure --target-list=arm-softmmu --enable-android $ make
~~~

As of this writing, Android versions up to 4.4.1 run fine in PANDROID, but anything newer than that won’t boot. Also, the Java level introspection code only works on the specific Dalvik runtime of Android 2.3. Anyways, older versions of Android seem to run much faster in the emulator, so if you plan on using PANDA sticking with Gingerbread is probably best. For more information, check out the extensive documentation in the PANDA git repo.

##### VxStripper

Another very useful tool built on QEMU is VxStripper by Sébastien Josse. VXStripper is specifically designed for de-obfuscating binaries. By instrumenting QEMU's dynamic binary translation mechanisms, it dynamically extracts an intermediate representation of a binary. It then applies simplifications to the extracted intermediate representation, and recompiles the simplified binary using LLVM. This is a very powerful way of normalizing obfuscated programs. See Sébastien's paper [14] for more information.

### Tampering and Instrumentation

#### Patching and Re-Packaging

##### Example 1: Repackaging an App for Debugging

1. Use apktool to restore AndroidManifest.xml:

```bash
$ apktool d --no-src target_app.apk
```

2. Add android:debuggable = “true” to the manifest:

```xml
<application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:name="com.xxx.xxx.xxx" android:theme="@style/AppTheme">
```

3. Repackage and sign the APK:

```bash
$ apktool b

$ zipalign -v 4 target_app.recompiled.apk  target_app.recompiled.aligned.apk

$ keytool -genkey -v -keystore ~/.android/debug.keystore -alias signkey -keyalg RSA -keysize 2048 -validity 20000

$ jarsigner -verbose -keystore ~/.android/debug.keystore  target_app.recompiled.aligned.apk signkey
```

4. Reinstall the app:

```bash
$ adb install target_app.recompiled.aligned.apk
```

##### Example 2: Disabling SSL Pinning

As seen in the previous Chapter, certificate pinning might hinder an analyst when analyzing the traffic. To help with this problem, the binary can be patched to allow other certificates. To demonstrate how Certificate Pinning can be bypassed, we will walk through the necessary steps to bypass Certificate Pinning implemented in an example application.
Disassembling the APK using apktool

```bash
$ apktool d target_apk.apk
```

Modify the Certificate Pinning logic:
We need to locate where within the smali source code the certificate pinning checks are done. Searching the smali code for keywords such as “X509TrustManager” should point you in the right direction.
In this case a search for “X509TrustManager” returned one class which implements an own Trustmanager. This file contains methods named “checkClientTrusted”, “checkServerTrusted” and “getAcceptedIssuers”.
The “return-void” opcode was added to the first line of each of these methods. The “return-void” statement is a Dalvik opcode to return ‘void’ or null. For more Dalvik opcodes refer to http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html.
In this context, return-void means that no certificate checks are performed and the application will accept all certificates.

```smali
.method public checkServerTrusted([LJava/security/cert/X509Certificate;Ljava/lang/String;)V
  .locals 3
  .param p1, "chain"	# [Ljava/security/cert/X509Certificate;
  .param p2, "authType"		# Ljava/lang/String;

  .prologue     
  return-void      # <-- OUR INSERTED OPCODE!
  .line 102
  iget-object v1, p0, Lasdf/t$a;->a:Ljava/util/ArrayList;

  invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

  move-result-object v1

  :goto_0
  invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z
```

#### Hooking Java Methods with Xposed

Xposed is a "framework for modules that can change the behavior of the system and apps without touching any APKs" [1]. Technically, it is an extended version of Zygote that exports APIs for running Java code when a new process is started. By running Java code in the context of the newly instantiated app, it is possible to resolve, hook and override Java methods belonging to the app. Xposed uses [reflection](https://docs.oracle.com/javase/tutorial/reflect/) to examine and modify the running app. Changes are applied in memory and persist only during the runtime of the process - no patches to the application files are made.

To use Xposed, you first need to install the Xposed framework on a rooted device. Modifications are then deployed in the form of separate apps ("modules") that can be toggled on and off in the Xposed GUI.

##### Example: Bypassing Root Detection

Let's assume you're testing an app that is stubbornly quitting on your rooted device. You decompile the app and find the following highly suspect method:

```java
package com.example.a.b

public static boolean c() {
  int v3 = 0;
  boolean v0 = false;

  String[] v1 = new String[]{"/sbin/", "/system/bin/", "/system/xbin/", "/data/local/xbin/",
    "/data/local/bin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/"};

    int v2 = v1.length;

    for(int v3 = 0; v3 < v2; v3++) {
      if(new File(String.valueOf(v1[v3]) + "su").exists()) {
         v0 = true;
         return v0;
      }
    }

    return v0;
}
```

This method iterates through a list of directories, and returns "true" (device rooted) if the "su" binary is found in any of them. Checks like this are easy to deactivate - all we have to do is to replace the code with something that returns "false".

Using an Xposed module is one way to do this. Modules for Xposed are developed and deployed with Android Studio just like regular Android apps. The author, rovo89, provides a great [tutorial](https://github.com/rovo89/XposedBridge/wiki/Development-tutorial) showing how to write, compile and install a module.

Code:

```java
package com.awesome.pentestcompany;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class DisableRootCheck implements IXposedHookLoadPackage {

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.targetapp"))
            return;

        findAndHookMethod("com.example.a.b", lpparam.classLoader, "c", new XC_MethodHook() {
            @Override

            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                XposedBridge.log("Caught root check!");
                param.setResult(false);
            }

        });
    }
}
```

#### Dynamic Instrumentation with FRIDA

Here are some more APIs FRIDA offers on Android:

-	Instantiate Java objects and call static and non-static class methods;
-	Replace Java method implementations;
-	Enumerate live instances of specific classes by scanning the Java heap (Dalvik only);
-	Scan process memory for occurrences of a string;
-	Intercept native function calls to run your own code at function entry and exit.

Some features unfortunately don’t work yet on current Android devices platforms. Most notably, the FRIDA Stalker - a code tracing engine based on dynamic recompilation - does not support ARM at the time of this writing (version 7.2.0). Also, support for ART has been included only recently, so the Dalvik runtime is still better supported.

##### Installing Frida

To install Frida locally, simply use Pypi:

~~~
$ sudo pip install frida
~~~

Your Android device needs to be rooted to get Frida running. Download the frida-server binary from the Frida releases page []. Make sure that the server version (at least the major version number) matches the version of your local Frida installation. Usually, Pypi will install the latest version of Frida, but if you are not sure, you can check with the Frida command line tool:

~~~
$ frida --version
9.1.10
$ wget https://github.com/frida/frida/releases/download/9.1.10/frida-server-9.1.10-android-arm.xz
~~~

Copy frida-server to the device and run it:

~~~
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "su -c /data/local/tmp/frida-server &"
~~~

With frida-server running, you should now be able to get a list of running processes with the following command:

~~~
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
 7617  com.dbs.digi.reluat
 7645  com.dbs.id.dbsdigibank
 7600  com.dbs.sit1.dbsmbanking
(...)
~~~

##### Example: Bypassing Native Debugger Detection

```python
#v0.1
 
import frida
import sys
 
session = frida.get_remote_device().attach("com.example.targetapp")
 
script = session.create_script("""
 
var funcPtr = Module.findExportByName("libdvm.so", "_Z25dvmDbgIsDebuggerConnectedv");
Interceptor.replace(funcPtr, new NativeCallback(function (pathPtr, flags) {
    return 0;
}, 'int', []));
""") 

def on_message(message, data):
    print(message)
 
script.on('message', on_message)
script.load()
sys.stdin.read()
```

### Program Comprehension

#### Decompiling and Analyzing Java Code

For the most part, Java bytecode can be converted back into source code without issues. Many free Java decompilers are available for doing this.

TODO: DEX vs. OAT

#### Statically Analyzing Native Code

#### Debugging Android Apps

Android apps support two different types of debugging: Java-runtime-level debugging using Java Debug Wire Protocol (JDWP) and Linux ptrace-style debugging on the native layer.

##### Debugging Java Code

JDWP debugging is used to debug Java code executed by the Android Runtime (ART). Consequently, it allows you to step through Java code, set breakpoints on Java methods, inspect instance variables of live objects, and many other useful things. JDWP is a standard debugging protocol that is supported by all command line tools and IDEs, including JDB, JEB, IntelliJ and Eclipse. You'll be using JDWP most of the time when debugging "normal" Android apps that don't do a lot of calls into native libraries.

The *adb* command line tool, which ships with the Android SDK, bridges the gap between your local development environment and a connected Android device. Commonly you'll debug on a device connected via USB, but remote debugging over the network is also possible.

TOOD ... command line JDB & native debugging ...

###### Debugging Using Decompiled Sources

A pretty neat trick is setting up a project in an IDE with the decompiled sources, which allows you to set method breakpoints directly in the source code. In most cases, you should be able single-step through the app, and inspect the state of variables through the GUI. The experience won't be perfect - its not the original source code after all, so you can't set line breakpoints and sometimes things will simply not work correctly. Then again, reversing code is never easy, and being able to efficiently navigate and debug plain old Java code is a pretty convenient way of doing it, so it's usually worth giving it a shot.


##### Debugging Native Code


#### Execution Tracing

Besides being useful for debugging, the JDB command line tool also offers basic execution tracing functionality. To trace an app right from the start we can pause the app using the Android "Wait for Debugger" feature or a kill –STOP command and attach JDB to set a deferred method breakpoint on an initialization method of our choice. Once the breakpoint hits, we activate method tracing with the trace go methods command and resume execution. JDB will dump all method entries and exits from that point on.

```bash
$ adb forward tcp:7777 jdwp:7288
$ { echo "suspend"; cat; } | jdb -attach localhost:7777
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> All threads suspended.
> stop in com.acme.bob.mobile.android.core.BobMobileApplication.<clinit>()          
Deferring breakpoint com.acme.bob.mobile.android.core.BobMobileApplication.<clinit>().
It will be set after the class is loaded.
> resume
All threads resumed.M
Set deferred breakpoint com.acme.bob.mobile.android.core.BobMobileApplication.<clinit>()

Breakpoint hit: "thread=main", com.acme.bob.mobile.android.core.BobMobileApplication.<clinit>(), line=44 bci=0
main[1] trace go methods
main[1] resume
Method entered: All threads resumed.
```

The Dalvik Debug Monitor Server (DDMS) a GUI tool included with Android Studio. At first glance it might not look like much, but make no mistake: Its Java method tracer is one of the most awesome tools you can have in your arsenal, and is indispensable for analyzing obfuscated bytecode.

Using DDMS is a bit confusing however: It can be launched in several ways, and different trace viewers will be launched depending on how the trace was obtained. There’s a standalone tool called “Traceview” as well as a built-in viewer in Android Studio, both of which offer different ways of navigating the trace. You’ll usually want to use the viewer built into Android studio (which I didn’t know about for several weeks until I discovered it by accident) which gives you a nice, zoom-able hierarchical timeline of all method calls. The standalone tool however is also useful, as it has a profile panel that shows the time spent in each method, as well as the parents and children of each method.

To record an execution trace in Android studio, open the “Android” tab at the bottom of the GUI. Select the target process in the list and the click the little “stop watch” button on the left. This starts the recording. Once you are done, click the same button to stop the recording. The integrated trace view will open showing the recorded trace. You can scroll and zoom the timeline view using the mouse or trackpad.

Alternatively, execution traces can also be recorded in the standalone Android Device Monitor. The Device Monitor can be started from within Android Studo (Tools -> Android -> Android Device Monitor) or from the shell with the ddms command.
To start recording tracing information, select the target process in the “Devices” tab and click the “Start Method Profiling” button. Click the stop button to stop recording, after which the Traceview tool will open showing the recorded trace. An interesting feature of the standalone tool is the “profile” panel on the bottom, which shows an overview of the time spent in each method, as well as each method’s parents and children. Clicking any of the methods in the profile panel highlights the selected method in the timeline panel.

As an aside, DDMS also offers convenient heap dump button that will dump the Java heap of a process to a .hprof file. More information on Traceview can be found in the Android Studio user guide.

#### Tracing System Calls

Moving down a level in the OS hierarchy, we arrive at privileged functions that require the powers of the Linux kernel. These functions are available to normal processes via the system call interface. Instrumenting and intercepting calls into the kernel is an effective method to get a rough idea of what a user process is doing, and is often the most efficient way to deactivate low-level tampering defenses.

Strace is a standard Linux utility that is used to monitor interaction between processes and the kernel. The utility is not included with Android by default, but can be easily built from source using the Android NDK. This gives us a very convenient way of monitoring system calls of a process. Strace however depends on ptrace() to attach to the target process, so it only works up to the point that anti- debugging measures kick in.

As a side note, if the Android “stop application at startup” feature is unavailable we can use a shell script to make sure that strace attached immediately once the process is launched (not an elegant solution but it works):

```bash
$ while true; do pid=$(pgrep 'target_process' | head -1); if [[ -n "$pid" ]]; then strace -s 2000 - e “!read” -ff -p "$pid"; break; fi; done
```

##### Ftrace

Ftrace is a tracing utility built directly into the Linux kernel. On a rooted device, ftrace can be used to trace kernel system calls in a more transparent way than is possible with strace, which relies on the ptrace system call to attach to the target process.
Conveniently, ftrace functionality is found in the stock Android kernel on both Lollipop and Marshmallow. It can be enabled with the following command:

```bash
$ echo 1 > /proc/sys/kernel/ftrace_enabled
```

The /sys/kernel/debug/tracing directory holds all control and output files and related to ftrace. The following files are found in this directory:

- available_tracers: This file lists the available tracers compiled into the kernel.
- current_tracer: This file is used to set or display the current tracer.
- tracing_on: Echo 1 into this file to allow/start update of the ring buffer. Echoing 0 will prevent further writes into the ring buffer.

##### KProbes

The KProbes interface provides us with an even more powerful way to instrument the kernel: It allows us to insert probes into (almost) arbitrary code addresses within kernel memory. Kprobes work by inserting a breakpoint instruction at the specified address. Once the breakpoint is hit, control passes to the Kprobes system, which then executes the handler function(s) defined by the user as well as the original instruction. Besides being great for function tracing, KProbes can be used to implement rootkit-like functionality such as file hiding.

Jprobes and Kretprobes are additional probe types based on Kprobes that allow hooking of function entries and exits.

Unfortunately, the stock Android kernel comes without loadable module support, which is a problem given that Kprobes are usually deployed as kernel modules. Another issue is that the Android kernel is compiled with strict memory protection which prevents patching some parts of Kernel memory. Using Elfmaster’s system call hooking method (5) results in a Kernel panic on default Lolllipop and Marshmallow due to sys_call_table being non-writable. We can however use Kprobes on a sandbox by compiling our own, more lenient Kernel (more on this later).

#### Emulation-based Analysis

Even in its standard form that ships with the Android SDK, the Android emulator – a.k.a. “emulator” - is a somewhat capable reverse engineering tool. It is based on QEMU, a generic and open source machine emulator. QEMU emulates a guest CPU by translating the guest instructions on-the-fly into instructions the host processor can understand. Each basic block of guest instructions is disassembled and translated into an intermediate representation called Tiny Code Generator (TCG). The TCG block is compiled into a block of host instructions, stored into a code cache, and executed. After execution of the basic block has completed, QEMU repeats the process for the next block of guest instructions (or loads the already translated block from the cache). The whole process is called dynamic binary translation.

Because the Android emulator is a fork of QEMU, it comes with the full QEMU feature set, including its monitoring, debugging and tracing facilities. QEMU-specific parameters can be passed to the emulator with the -qemu command line flag. We can use QEMU’s built-in tracing facilities to log executed instructions and virtual register values. Simply starting qemu with the "-d" command line flag will cause it to dump the blocks of guest code, micro operations or host instructions being executed. The –d in_asm option logs all basic blocks of guest code as they enter QEMU’s translation function. The following command logs all translated blocks to a file:

```bash
$ emulator -show-kernel -avd Nexus_4_API_19 -snapshot default-boot -no-snapshot-save -qemu -d in_asm,cpu 2>/tmp/qemu.log
```

Unfortunately, it is not possible to generate a complete guest instruction trace with QEMU, because code blocks are written to the log only at the time they are translated – not when they’re taken from the cache. For example, if a block is repeatedly executed in a loop, only the first iteration will be printed to the log. There’s no way to disable TB caching in QEMU (save for hacking the source code). Even so, the functionality is sufficient for basic tasks, such as reconstructing the disassembly of a natively executed cryptographic algorithm.

Dynamic analysis frameworks, such as PANDA and DroidScope, build on QEMU to provide more complete tracing functionality. PANDA/PANDROID is your best if you’re going for a CPU-trace based analysis, as it allows you to easily record and replay a full trace, and is relatively easy to set up if you follow the build instructions for Ubuntu.

#### Customizing Android

Working on real device has advantages especially for interactive, debugger-supported static / dynamic analysis. For one, it is simply faster to work on a real device. Also, being run on a real device gives the target app less reason to be suspicious and misbehave. By instrumenting the live environment at strategic points, we can obtain useful tracing functionality and manipulate the environment to help us bypass any anti-tampering defenses the app might implement.

##### Preparing a development environment

To get the development environment ready, simply download Google’s Android Studio. It comes with a SDK Manager app that lets you install the Android SDK tools and manage SDKs for various API levels, as well as the emulator and an AVD Manager application to create emulator images. Android Studio can be downloaded from the Android download page:

https://developer.android.com/develop/index.html

You’ll also need the Android NDK for compiling anything that creates native code. The NDK contains prebuilt toolchains for cross-compiling native code for different architectures. The NDK is available as a separate download:
https://developer.android.com/ndk/downloads/index.html

After you downloaded the SDK, create a standalone toolchain for Android Lollipop (API 21):

```bash
$ $YOUR_NDK_PATH/build/tools/make-standalone-toolchain.sh --arch=arm --platform=android-21 --install-dir=/tmp/my-android-toolchain
```

##### Customizing the RAMDisk

The initramfs is a small CPIO archive stored inside the boot image. It contains a few files that are required at boot time before the actual root file system is mounted. On Android, the initramfs stays mounted indefinitely, and it contains an important configuration file named default.prop that defines some basic system properties. By making some changes to this file, we can make the Android environment a bit more reverse-engineering-friendly.
For our purposes, the most important settings in default.prop are ro.debuggable and ro.secure.

```bash
$ cat /default.prop                                         
#
# ADDITIONAL_DEFAULT_PROPERTIES
#
ro.secure=1
ro.allow.mock.location=0
ro.debuggable=1
ro.zygote=zygote32
persist.radio.snapshot_enabled=1
persist.radio.snapshot_timer=2
persist.radio.use_cc_names=true
persist.sys.usb.config=mtp
rild.libpath=/system/lib/libril-qc-qmi-1.so
camera.disable_zsl_mode=1
ro.adb.secure=1
dalvik.vm.dex2oat-Xms=64m
dalvik.vm.dex2oat-Xmx=512m
dalvik.vm.image-dex2oat-Xms=64m
dalvik.vm.image-dex2oat-Xmx=64m
ro.dalvik.vm.native.bridge=0
```

Setting ro.debuggable to 1 causes all apps running on the system to be debuggable (i.e., the debugger thread runs in every process), independent of the android:debuggable attribute in the app’s Manifest. Setting ro.secure to 0 causes adbd to be run as root.
To modify initrd on any Android device, back up the original boot image using TWRP, or simply dump it with a command like:

```bash
$ adb shell cat /dev/mtd/mtd0 >/mnt/sdcard/boot.img
$ adb pull /mnt/sdcard/boot.img /tmp/boot.img
```

Use the abootimg tool as described in Krzysztof Adamski’s how-to to extract the contents of the boot image:

```bash
$ mkdir boot
$ cd boot
$ ../abootimg -x /tmp/boot.img
$ mkdir initrd
$ cd initrd
$ cat ../initrd.img | gunzip | cpio -vid
```

Take note of the boot parameters written to bootimg.cfg – you will need to these parameters later when booting your new kernel and ramdisk.

```bash
$ ~/Desktop/abootimg/boot$ cat bootimg.cfg
bootsize = 0x1600000
pagesize = 0x800
kerneladdr = 0x8000
ramdiskaddr = 0x2900000
secondaddr = 0xf00000
tagsaddr = 0x2700000
name =
cmdline = console=ttyHSL0,115200,n8 androidboot.hardware=hammerhead user_debug=31 maxcpus=2 msm_watchdog_v2.enable=1
```

Modify default.prop and package your new ramdisk:

```bash
$ cd initrd
$ find . | cpio --create --format='newc' | gzip > ../myinitd.img
```

##### Customizing the Android Kernel

The Android kernel is a powerful ally to the reverse engineer. While regular Android apps are hopelessly restricted and sandboxed, you - the reverser - can customize and alter the behavior of the operating system and kernel any way you wish. This gives you a really unfair advantage, because most integrity checks and anti-tampering features ultimately rely on services performed by the kernel. Deploying a kernel that abuses this trust, and unabashedly lies about itself and the environment, goes a long way in defeating most reversing defenses that malware authors (or normal developers) can throw at you.

Android apps have several ways of interacting with the OS environment. The standard way is through the APIs of the Android Application Framework. On the lowest level however, many important functions, such as allocating memory and accessing files, are translated into perfectly old-school Linux system calls. In ARM Linux, system calls are invoked via the SVC instruction which triggers a software interrupt. This interrupt calls the vector_swi() kernel function, which then uses the system call number as an offset into a table of function pointers (a.k.a. sys_call_table on Android).

The most straightforward way of intercepting system calls is injecting your own code into kernel memory, then overwriting the original function in the system call table to redirect execution. Unfortunately, current stock Android kernels enforce memory restrictions that prevent this from working. Specifically, stock Lollipop and Marshmallow kernel are built with the CONFIG_STRICT_MEMORY_RWX option enabled. This prevents writing to kernel memory regions marked as read-only, which means that any attempts to patch kernel code or the system call table result in a segmentation fault and reboot. A way to get around this is to build your own kernel: You can then deactivate this protection, and make many other useful customizations to make reverse engineering easier. If you're reversing Android apps on a regular basis, building your own reverse engineering sandbox is a no-brainer.

For hacking purposes, I recommend using an AOSP-supported device. Google’s Nexus smartphones and tablets are the most logical candidates – kernels and system components built from the AOSP run on them without issues. Alternatively, Sony’s Xperia series is also known for its openness. To build the AOSP kernel you need a toolchain (set of programs to cross-compile the sources) as well as the appropriate version of the kernel sources. Follow Google's instructions to identify the correct git repo and branch for a given device and Android version.

https://source.android.com/source/building-kernels.html#id-version

For example, to get kernel sources for Lollipop that are compatible with the Nexus 5, you need to clone the "msm" repo and check out one the "android-msm-hammerhead" branch (hammerhead is the codenam” of the Nexus 5, and yes, finding the right branch is a confusing process). Once the sources are downloaded, create the default kernel config with the command make hammerhead_defconfig (or whatever_defconfig, depending on your target device).

```bash
$ git clone https://android.googlesource.com/kernel/msm.git
$ cd msm
$ git checkout origin/android-msm-hammerhead-3.4-lollipop-mr1
$ export ARCH=arm
$ export SUBARCH=arm
$ make hammerhead_defconfig
$ vim .config
```

I recommend using the following settings to enable the most important tracing facilities, add loadable module support, and open up kernel memory for patching.

```
CONFIG_MODULES=Y
CONFIG_STRICT_MEMORY_RWX=N
CONFIG_DEVMEM=Y
CONFIG_DEVKMEM=Y
CONFIG_KALLSYMS=Y
CONFIG_KALLSYMS_ALL=Y
CONFIG_HAVE_KPROBES=Y
CONFIG_HAVE_KRETPROBES=Y
CONFIG_HAVE_FUNCTION_TRACER=Y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=Y
CONFIG_TRACING=Y
CONFIG_FTRACE=Y
CONFIG KDB=Y
```

Once you are finished editing save the .config file and build the kernel.

```bash
$ export ARCH=arm
$ export SUBARCH=arm
$ export CROSS_COMPILE=/path_to_your_ndk/arm-eabi-4.8/bin/arm-eabi-
$ make
```

Once you are finished editing save the .config file. Optionally, you can now create a standalone toolchain for cross-compiling the kernel and later tasks. To create a toolchain for Android 5.1, run make-standalone-toolchain.sh from the Android NDK package as follows:

```bash
$ cd android-ndk-rXXX
$ build/tools/make-standalone-toolchain.sh --arch=arm --platform=android-21 --install-dir=/tmp/my-android-toolchain
```

Set the CROSS_COMPILE environment variable to point to your NDK directory and run "make" to build
the kernel.

```bash
$ export CROSS_COMPILE=/tmp/my-android-toolchain/bin/arm-eabi-
$ make
```

##### Booting the Custom Environment

Before booting into the new Kernel, make a copy of the original boot image from your device. Look up the location of the boot partition as follows:

```bash
root@hammerhead:/dev # ls -al /dev/block/platform/msm_sdcc.1/by-name/         
lrwxrwxrwx root     root              1970-08-30 22:31 DDR -> /dev/block/mmcblk0p24
lrwxrwxrwx root     root              1970-08-30 22:31 aboot -> /dev/block/mmcblk0p6
lrwxrwxrwx root     root              1970-08-30 22:31 abootb -> /dev/block/mmcblk0p11
lrwxrwxrwx root     root              1970-08-30 22:31 boot -> /dev/block/mmcblk0p19
(...)
lrwxrwxrwx root     root              1970-08-30 22:31 userdata -> /dev/block/mmcblk0p28
```

Then, dump the whole thing into a file:

```bash
$ adb shell "su -c dd if=/dev/block/mmcblk0p19 of=/data/local/tmp/boot.img"
$ adb pull /data/local/tmp/boot.img
```

Next, extract the ramdisk as well as some information about the structure of the boot image. There are various tools that can do this - I used Gilles Grandou's abootimg tool. Install the tool and run the following command on your boot image:

```bash
$ abootimg -x boot.img
```

This should create the files bootimg.cfg, initrd.img and zImage (your original kernel) in the local directory.

You can now use fastboot to test the new kernel. The "fastboot boot" command allows you to run the kernel without actually flashing it (once you’re sure everything works, you can make the changes permanent with fastboot flash - but you don't have to). Restart the device in fastboot mode with the following command:

```bash
$ adb reboot bootloader
```

Then, use the "fastboot boot" command to boot Android with the new kernel. In addition to the newly built kernel and the original ramdisk, specify the kernel offset, ramdisk offset, tags offset and commandline (use the values listed in your previously extracted bootimg.cfg).

```bash
$ fastboot boot zImage-dtb initrd.img --base 0 --kernel-offset 0x8000 --ramdisk-offset 0x2900000 --tags-offset 0x2700000 -c "console=ttyHSL0,115200,n8 androidboot.hardware=hammerhead user_debug=31 maxcpus=2 msm_watchdog_v2.enable=1"
```

The system should now boot normally. To quickly verify that the correct kernel is running, navigate to Settings->About phone and check the “kernel version” field.

![Disassembly of function main.](Images/Chapters/0x05c/custom_kernel.jpg)

##### System Call Hooking Using Kernel Modules

System call hooking allows us to attack any anti-reversing defenses that depend on functionality provided by the kernel. With our custom kernel in place, we can now use a LKM to load additional code into the kernel. We also have access to the /dev/kmem interface, which we can use to patch kernel memory on-the-fly. This is a classical Linux rootkit technique and has been described for Android by Dong-Hoon You [1].

![Disassembly of function main.](Images/Chapters/0x05c/syscall_hooking.jpg)

The first piece of information we need is the address of sys_call_table. Fortunately, it is exported as a symbol in the Android kernel (iOS reversers are not so lucky). We can look up the address in the /proc/kallsyms file:

```bash
$ adb shell "su -c echo 0 > /proc/sys/kernel/kptr_restrict"
$ adb shell cat /proc/kallsyms | grep sys_call_table
c000f984 T sys_call_table
```

This is the only memory address we need for writing our kernel module - everything else can be calculated using offsets taken from the Kernel headers (hopefully you didn't delete them yet?).

###### Example: File Hiding

In this howto, we're going to use a Kernel module to hide a file. Let's create a file on the device so we can hide it later:

$ adb shell "su -c echo ABCD > /data/local/tmp/nowyouseeme"             
$ adb shell cat /data/local/tmp/nowyouseeme
ABCD
Finally it's time to write the kernel module. For file hiding purposes, we'll need to hook one of the system calls used to open (or check for the existence of) files. Actually, there many of those - open, openat, access, accessat, facessat, stat, fstat, and more. For now, we'll only hook the openat system call - this is the syscall used by the "/bin/cat" program when accessing a file, so it should be servicable enough for a demonstration.

You can find the function prototypes for all system calls in the kernel header file arch/arm/include/asm/unistd.h. Create a file called kernel_hook.c with the following code:

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

asmlinkage int (*real_openat)(int, const char __user*, int);

void **sys_call_table;

int new_openat(int dirfd, const char \__user* pathname, int flags)
{
  char *kbuf;
  size_t len;

  kbuf=(char*)kmalloc(256,GFP_KERNEL);
  len = strncpy_from_user(kbuf,pathname,255);

  if (strcmp(kbuf, "/data/local/tmp/nowyouseeme") == 0) {
    printk("Hiding file!\n");
    return -ENOENT;
  }

  kfree(kbuf);

  return real_openat(dirfd, pathname, flags);
}

int init_module() {

  sys_call_table = (void*)0xc000f984;
  real_openat = (void*)(sys_call_table[__NR_openat]);

return 0;

}
```

To build the kernel module, you need the kernel sources and a working toolchain - since you already built a complete kernel before, you are all set. Create a Makefile with the following content:

```make
KERNEL=[YOUR KERNEL PATH]
TOOLCHAIN=[YOUR TOOLCHAIN PATH]

obj-m := kernel_hook.o

all:
        make ARCH=arm CROSS_COMPILE=$(TOOLCHAIN)/bin/arm-eabi- -C $(KERNEL) M=$(shell pwd) CFLAGS_MODULE=-fno-pic modules

clean:
        make -C $(KERNEL) M=$(shell pwd) clean
```

Run "make" to compile the code – this should create the file kernel_hook.ko. Copy the kernel_hook.ko file to the device and load it with the insmod command. Verify with the lsmod command that the module has been loaded successfully.

```bash
$ make
(...)
$ adb push kernel_hook.ko /data/local/tmp/
[100%] /data/local/tmp/kernel_hook.ko
$ adb shell su -c insmod /data/local/tmp/kernel_hook.ko
$ adb shell lsmod
kernel_hook 1160 0 [permanent], Live 0xbf000000 (PO)
```

Now, we’ll access /dev/kmem to overwrite the original function pointer in sys_call_table with the address of our newly injected function (this could have been done directly in the kernel module as well, but using /dev/kmem gives us an easy way to toggle our hooks on and off). I have adapted the code from Dong-Hoon You’s Phrack article [1] for this purpose - however, I used the file interface instead of mmap(), as I found the latter to cause kernel panics for some reason. Create a file called kmem_util.c with the following code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <sys/mman.h>

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

int kmem;
void read_kmem2(unsigned char *buf, off_t off, int sz)
{
  off_t offset; ssize_t bread;
  offset = lseek(kmem, off, SEEK_SET);
  bread = read(kmem, buf, sz);
  return;
}

void write_kmem2(unsigned char *buf, off_t off, int sz) {
  off_t offset; ssize_t written;
  offset = lseek(kmem, off, SEEK_SET);
  if (written = write(kmem, buf, sz) == -1) { perror("Write error");
    exit(0);
  }
  return;
}

int main(int argc, char *argv[]) {

  off_t sys_call_table;
  unsigned int addr_ptr, sys_call_number;

  if (argc < 3) {
    return 0;
  }

  kmem=open("/dev/kmem",O_RDWR);

  if(kmem<0){
    perror("Error opening kmem"); return 0;
  }

  sscanf(argv[1], "%x", &sys_call_table); sscanf(argv[2], "%d", &sys_call_number);
  sscanf(argv[3], "%x", &addr_ptr); char buf[256];
  memset (buf, 0, 256); read_kmem2(buf,sys_call_table+(sys_call_number*4),4);
  printf("Original value: %02x%02x%02x%02x\n", buf[3], buf[2], buf[1], buf[0]);       
  write_kmem2((void*)&addr_ptr,sys_call_table+(sys_call_number*4),4);
  read_kmem2(buf,sys_call_table+(sys_call_number*4),4);
  printf("New value: %02x%02x%02x%02x\n", buf[3], buf[2], buf[1], buf[0]);
  close(kmem);

  return 0;
}
```

Build kmem_util.c using the prebuilt toolchain and copy it to the device. Note that from Android Lollipop, all executables must be compiled with PIE support:

```bash
$ /tmp/my-android-toolchain/bin/arm-linux-androideabi-gcc -pie -fpie -o kmem_util kmem_util.c
$ adb push kmem_util /data/local/tmp/
$ adb shell chmod 755 /data/local/tmp/kmem_util
```

Before we start messing with kernel memory we still need to know the correct offset into the system call table. The openat system call is defined in unistd.h which is found in the kernel sources:

```bash
$ grep -r "__NR_openat" arch/arm/include/asm/unistd.h
#define __NR_openat            (__NR_SYSCALL_BASE+322)
```

The final piece of the puzzle is the address of our replacement-openat. Again, we can get this address from /proc/kallsyms.

```bash
$ adb shell cat /proc/kallsyms | grep new_openat
bf000000 t new_openat    [kernel_hook]
```

Now we have everything we need to overwrite the sys_call_table entry. The syntax for kmem_util is:

```bash
./kmem_util <syscall_table_base_address> <offset> <func_addr>
```

The following command patches the openat system call table to point to our new function.

```bash
$ adb shell su -c /data/local/tmp/kmem_util c000f984 322 bf000000
Original value: c017a390
New value: bf000000
```

Assuming that everything worked, /bin/cat should now be unable to "see" the file.

```bash
$ adb shell su -c cat /data/local/tmp/nowyouseeme
tmp-mksh: cat: /data/local/tmp/nowyouseeme: No such file or directory
```

Voilá! The file "nowyouseeme" is now somewhat hidden from the view of all usermode processes (note that there's a lot more you need to do to properly hide a file, including hooking stat(), access(), and other system calls, as well as hiding the file in directory listings).

File hiding is of course only the tip of the iceberg: You can accomplish a whole lot of things, including bypassing many root detection measures, integrity checks, and anti-debugging tricks. You can find some additional examples in the "case studies" section in [x]

### Automating Binary Analysis Tasks

Binary analysis frameworks provide you powerful ways of automating tasks that would be almost impossible to complete manually. In the section, we'll have a look at the Angr framework, a python framework for analyzing binaries that is useful for both static and dynamic symbolic ("concolic") analysis. Angr operates on the VEX intermediate language, and comes with a loader for ELF/ARM binaries, so it is perfect for dealing with native Android binaries.

Our target program is a simple license key validation program. Granted, you won't usually find a license key validator like this in the wild, but it should be useful enough to demonstrate the basics of static/symbolic analysis of native code. You can use the same techniques on Android apps that ship with obfuscated native libraries (in fact, obfuscated code is often put into native libraries, precisely to make de-obfuscation more difficult).

#### Installing Angr

Angr is written in Python 2 and available from PyPI. It is easy to install on \*nix operating systems and Mac OS using pip:

```
$ pip install angr
```

It is recommended to create a dedicated virtual environment with Virtualenv as some of its dependencies contain forked versions Z3 and PyVEX that overwrite the original versions (you may skip this step if you don't use these libraries for anything else - on the other hand, using Virtualenv is generally a good idea).

Quite comprehensive documentation for angr is available on Gitbooks, including an installation guide, tutorials and usage examples [5]. A complete API reference is also available [6].

##### Using the Disassembler Backends

<a name="symbolicexec"></a>
##### Symbolic Execution

Symbolic execution allows you to determine the conditions necessary to reach a specific target. It does this by translating the program’s semantics into a logical formula, whereby some variables are represented as symbols with specific constraints. By resolving the constraints, you can find out the conditions necessary so that some branch of the program gets executed.

Amongst other things, this is useful in cases where we need to find the right inputs for reaching a certain block of code. In the following example, we'll use Angr to solve a simple Android crackme in an automated fashion. The crackme takes the form of a native ELF binary that can be downloaded here:

https://github.com/angr/angr-doc/tree/master/examples/android_arm_license_validation

Running the executable on any Android device should give you the following output.

```bash
$ adb push validate /data/local/tmp
[100%] /data/local/tmp/validate
$ adb shell chmod 755 /data/local/tmp/validate
$ adb shell /data/local/tmp/validate
Usage: ./validate <serial>
$ adb shell /data/local/tmp/validate 12345
Incorrect serial (wrong format).
```

So far, so good, but we really know nothing about how a valid license key might look like. Where do we start? Let's fire up IDA Pro to get a first good look at what is happening.

![Disassembly of function main.](Images/Chapters/0x05c/license-check-1.jpg)

The main function is located at address 0x1874 in the disassembly (note that this is a PIE-enabled binary, and IDA Pro chooses 0x0 as the image base address). Function names have been stripped, but luckily we can see some references to debugging strings: It appears that the input string is base32-decoded (call to sub_1340). At the beginning of main, there's also a length check at loc_1898 that verifies that the length of the input string is exactly 16. So we're looking for a 16 character base32-encoded string! The decoded input is then passed to the function sub_1760, which verifies the validity of the license key.

The 16-character base32 input string decodes to 10 bytes, so we know that the validation function expects a 10 byte binary string. Next, we have a look at the core validation function at 0x1760:

```assembly_x68
.text:00001760 ; =============== S U B R O U T I N E =======================================
.text:00001760
.text:00001760 ; Attributes: bp-based frame
.text:00001760
.text:00001760 sub_1760                                ; CODE XREF: sub_1874+B0
.text:00001760
.text:00001760 var_20          = -0x20
.text:00001760 var_1C          = -0x1C
.text:00001760 var_1B          = -0x1B
.text:00001760 var_1A          = -0x1A
.text:00001760 var_19          = -0x19
.text:00001760 var_18          = -0x18
.text:00001760 var_14          = -0x14
.text:00001760 var_10          = -0x10
.text:00001760 var_C           = -0xC
.text:00001760
.text:00001760                 STMFD   SP!, {R4,R11,LR}
.text:00001764                 ADD     R11, SP, #8
.text:00001768                 SUB     SP, SP, #0x1C
.text:0000176C                 STR     R0, [R11,#var_20]
.text:00001770                 LDR     R3, [R11,#var_20]
.text:00001774                 STR     R3, [R11,#var_10]
.text:00001778                 MOV     R3, #0
.text:0000177C                 STR     R3, [R11,#var_14]
.text:00001780                 B       loc_17D0
.text:00001784 ; ---------------------------------------------------------------------------
.text:00001784
.text:00001784 loc_1784                                ; CODE XREF: sub_1760+78
.text:00001784                 LDR     R3, [R11,#var_10]
.text:00001788                 LDRB    R2, [R3]
.text:0000178C                 LDR     R3, [R11,#var_10]
.text:00001790                 ADD     R3, R3, #1
.text:00001794                 LDRB    R3, [R3]
.text:00001798                 EOR     R3, R2, R3
.text:0000179C                 AND     R2, R3, #0xFF
.text:000017A0                 MOV     R3, #0xFFFFFFF0
.text:000017A4                 LDR     R1, [R11,#var_14]
.text:000017A8                 SUB     R0, R11, #-var_C
.text:000017AC                 ADD     R1, R0, R1
.text:000017B0                 ADD     R3, R1, R3
.text:000017B4                 STRB    R2, [R3]
.text:000017B8                 LDR     R3, [R11,#var_10]
.text:000017BC                 ADD     R3, R3, #2
.text:000017C0                 STR     R3, [R11,#var_10]
.text:000017C4                 LDR     R3, [R11,#var_14]
.text:000017C8                 ADD     R3, R3, #1
.text:000017CC                 STR     R3, [R11,#var_14]
.text:000017D0
.text:000017D0 loc_17D0                                ; CODE XREF: sub_1760+20
.text:000017D0                 LDR     R3, [R11,#var_14]
.text:000017D4                 CMP     R3, #4
.text:000017D8                 BLE     loc_1784
.text:000017DC                 LDRB    R4, [R11,#var_1C]
.text:000017E0                 BL      sub_16F0
.text:000017E4                 MOV     R3, R0
.text:000017E8                 CMP     R4, R3
.text:000017EC                 BNE     loc_1854
.text:000017F0                 LDRB    R4, [R11,#var_1B]
.text:000017F4                 BL      sub_170C
.text:000017F8                 MOV     R3, R0
.text:000017FC                 CMP     R4, R3
.text:00001800                 BNE     loc_1854
.text:00001804                 LDRB    R4, [R11,#var_1A]
.text:00001808                 BL      sub_16F0
.text:0000180C                 MOV     R3, R0
.text:00001810                 CMP     R4, R3
.text:00001814                 BNE     loc_1854
.text:00001818                 LDRB    R4, [R11,#var_19]
.text:0000181C                 BL      sub_1728
.text:00001820                 MOV     R3, R0
.text:00001824                 CMP     R4, R3
.text:00001828                 BNE     loc_1854
.text:0000182C                 LDRB    R4, [R11,#var_18]
.text:00001830                 BL      sub_1744
.text:00001834                 MOV     R3, R0
.text:00001838                 CMP     R4, R3
.text:0000183C                 BNE     loc_1854
.text:00001840                 LDR     R3, =(aProductActivat - 0x184C)
.text:00001844                 ADD     R3, PC, R3      ; "Product activation passed. Congratulati"...
.text:00001848                 MOV     R0, R3          ; char *
.text:0000184C                 BL      puts
.text:00001850                 B       loc_1864
.text:00001854 ; ---------------------------------------------------------------------------
.text:00001854
.text:00001854 loc_1854                                ; CODE XREF: sub_1760+8C
.text:00001854                                         ; sub_1760+A0 ...
.text:00001854                 LDR     R3, =(aIncorrectSer_0 - 0x1860)
.text:00001858                 ADD     R3, PC, R3      ; "Incorrect serial."
.text:0000185C                 MOV     R0, R3          ; char *
.text:00001860                 BL      puts
.text:00001864
.text:00001864 loc_1864                                ; CODE XREF: sub_1760+F0
.text:00001864                 SUB     SP, R11, #8
.text:00001868                 LDMFD   SP!, {R4,R11,PC}
.text:00001868 ; End of function sub_1760
```

We can see a loop with some XOR-magic happening at loc_1784, which supposedly decodes the input string. Starting from loc_17DC, we see a series of comparisons of the decoded values with values obtained from further sub-function calls. Even though this doesn't look like highly sophisticated stuff, we'd still need to do some more analysis to completely reverse this check and generate a license key that passes it. But now comes the twist: By using dynamic symbolic execution, we can construct a valid key automatically! The symbolic execution engine can map a path between the first instruction of the license check (0x1760) and the code printing the "Product activation passed" message (0x1840) and determine the constraints on each byte of the input string. The solver engine then finds an input that satisfies those constraints: The valid license key.

We need to provide several inputs to the symbolic execution engine:

- The address to start execution from. We initialize the state with the first instruction of the serial validation function. This makes the task significantly easier (and in this case, almost instant) to solve, as we avoid symbolically executing the Base32 implementation.

- The address of the code block we want execution to reach. In this case, we want to find a path to the code responsible for printing the "Product activation passed" message. This block starts at 0x1840.

- Addresses we don't want to reach. In this case, we're not interesting in any path that arrives at the block of code printing the "Incorrect serial" message, at 0x1854.

Note that Angr loader will load the PIE executable with a base address of 0x400000, so we have to add this to the addresses above. The solution looks as follows.

```python
#!/usr/bin/python

# This is how we defeat the Android license check using Angr!
# The binary is available for download on GitHub:
# https://github.com/b-mueller/obfuscation-metrics/tree/master/crackmes/android/01_license_check_1
# Written by Bernhard -- bernhard [dot] mueller [at] owasp [dot] org

import angr
import claripy
import base64

load_options = {}

# Android NDK library path:
load_options['custom_ld_path'] = ['/Users/berndt/Tools/android-ndk-r10e/platforms/android-21/arch-arm/usr/lib']

b = angr.Project("./validate", load_options = load_options)

# The key validation function starts at 0x401760, so that's where we create the initial state.
# This speeds things up a lot because we're bypassing the Base32-encoder.

state = b.factory.blank_state(addr=0x401760)

initial_path = b.factory.path(state)
path_group = b.factory.path_group(state)

# 0x401840 = Product activation passed
# 0x401854 = Incorrect serial

path_group.explore(find=0x401840, avoid=0x401854)
found = path_group.found[0]

# Get the solution string from *(R11 - 0x24).

addr = found.state.memory.load(found.state.regs.r11 - 0x24, endness='Iend_LE')
concrete_addr = found.state.se.any_int(addr)
solution = found.state.se.any_str(found.state.memory.load(concrete_addr,10))

print base64.b32encode(solution)
```

Note the last part of the program where the final input string is obtained - it appears if we were simply reading the solution from memory. We are however reading from symbolic memory - neither the string nor the pointer to it actually exist! What's really happening is that the solver is computing possible concrete values that could be found at that program state, would we observer the actual program run to that point.

Running this script should return the following:

```
(angr) $ python solve.py
WARNING | 2017-01-09 17:17:03,664 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
JQAE6ACMABNAAIIA
```

### References

- [1] APKTool -
- [2] JD - http://jd.benow.ca/
- [3] Eclipse
- [4] IntelliJ IDEA - https://www.jetbrains.com/idea/
- [5] Smalidea -
- [6] Radare2 -
- [7] Angr -
- [8] JEB -
- [9] IDA Pro -
- [10] DroidScope -
- [11] DECAF - https://github.com/sycurelab/DECAF
- [12] PANDA - https://github.com/moyix/panda/blob/master/docs/
- [13] VxStripper -
- [14] Dynamic Malware Recompliation - http://ieeexplore.ieee.org/document/6759227/
- [X] http://repo.xposed.info/module/de.robv.android.xposed.installer
- [X] https://github.com/rovo89/XposedBridge/wiki/Development-tutorial
- [X] https://github.com/JesusFreke/smali
- [X] https://dl.packetstormsecurity.net/papers/general/HITB_Hacking_Soft_Tokens_v1.2.pdf
- [X] https://en.wikipedia.org/wiki/Concolic_testing
