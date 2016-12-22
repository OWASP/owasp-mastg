## Tampering and Reverse Engineering on Android

Its openness makes Android a favorable environment for reverse engineers. However, dealing with both Java and native code can make things more complicated at times. In the following chapter, we'll look at some peculiarities of Android reversing and OS-specific tools as processes.

### Basics

In comparison to iOS, Android offers some big advantages to reverse engineers. First of all transparency: You can study the source code of the Android Open Source Project (AOSP), build your ROMs, and so on. The OS is also much more friendly to developers and tinkerers in other way: From the developer options available by default, to the way debugging is set up and the tools shipping with the SDK, there's lot of niceties to make your life easier compared to "some other vendors".

However, there's also a few challenges you'll encounter. For example, if you're used to analyzing native code, you'll need to add Java bytecode to your repertoire. As it is easy for developers to call into native code via the Java Native Interface (JNI), you'll often need to work with Java and native code at the same time. JNI is sometimes used on purpose to confuse reverse engineers (to be fair, there might also be legitimate reasons for using JNI, such as improving performance or supporting legacy code). Developers seeking to impede reverse engineering deliberately split functionality between Java bytecode and native code, structuring their apps such that execution frequently jumps between the two layers.

Android reverse engineers need to understand both Java bytecode and ARM assembler, and have a working knowledge about both the Java-based Android environment and the Linux OS and Kernel that forms the basis of Android (better yet, they’d know all these things inside out). Plus, they need the right toolset to deal with both native code and bytecode running inside the Java virtual machine.

### Environment and Toolset

With a little effort you can build a reasonable reverse engineering environment for free. JD is a free Java de-compiler that integrates with Eclipse and IntelliJ. Generally, IntelliJ is the more light-weight solution and works great for browsing the source code and also allows for basic on-device debugging of the decompiled apps.

If you don’t mind looking at SMALI instead of Java code, you can use the smalidea plugin for IntelliJ for debugging on the device. According to the website, Smalidea supports single-stepping through the bytecode, identifier renaming and watches for non-named registers, which makes it much more powerful than a JD + IntelliJ setup.

APKTool is a mandatory utility for dealing with APK archives. It can extract and disassemble resources directly from the APK archive, and can disassemble Java bytecode to SMALI. It also allows you to reassemble the APK package, which is useful for patching and making changes to the Manifest.
https://github.com/JesusFreke/smali

IDA Pro understands ARM, MIPS and of course Intel ELF binaries, plus it can deal with Java bytecode. It also comes with remote debuggers for both Java applications and native processes. With its great disassembler and powerful scripting and extension capabilities, IDA Pro is the unbeaten king for static analysis of native programs and libraries. However, the static analysis facilities it offers for Java code are somewhat basic – you get the SMALI disassembly but not much more. There’s no navigating the package and class structure, and some things (such as renaming classes) can’t be done which can make working with larger obfuscated apps a bit tedious.

This is where dedicated Java de-compilers become useful. JEB, a commercial decompiler, outs all the functionality one might need in a convenient-to-use all-in-one package, is reasonably reliable and you get quick support. It also has a built-in debugger, which allows for an efficient workflow – setting breakpoints directly in the annotated sources is invaluable, especially when dealing with ProGuard-obfuscated bytecode. Unfortunately, convenience like this doesn’t come cheap - at $90 / month for the standard license, JEB isn’t exactly a steal.

-- TODO: Other tools

Some things that should be mentioned:

- Android SDK
- Smali and Baksmali
- Androguard
- apktool
- ADB
- DexDump
- dex2jar

### Manipulating Android Apps

#### Patching and Re-Packaging

##### Example 1: Repackaging an App for Debugging

1. Use apktool to restore AndroidManifest.xml:

~~~~
$ apktool d --no-src target_app.apk
~~~~

2. Add android:debuggable = “true” to the manifest:

~~~~
<application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:name="com.xxx.xxx.xxx" android:theme="@style/AppTheme">
~~~~

3. Repackage and sign the APK:

~~~~
$ apktool b

$ zipalign -v 4 target_app.recompiled.apk  target_app.recompiled.aligned.apk

$ keytool -genkey -v -keystore ~/.android/debug.keystore -alias signkey -keyalg RSA -keysize 2048 -validity 20000

$ jarsigner -verbose -keystore ~/.android/debug.keystore  target_app.recompiled.aligned.apk signkey
~~~~

4. Reinstall the app:

~~~
$ adb install target_app.recompiled.aligned.apk
~~~

##### Example 2: Disabling SSL Pinning

As seen in the previous Chapter, certificate pinning might hinder an analyst when analyzing the traffic. To help with this problem, the binary can be patched to allow other certificates. To demonstrate how Certificate Pinning can be bypassed, we will walk through the necessary steps to bypass Certificate Pinning implemented in an example application.
Disassembling the APK using apktool

~~~
$ apktool d target_apk.apk
~~~

Modify the Certificate Pinning logic:
We need to locate where within the smali source code the certificate pinning checks are done. Searching the smali code for keywords such as “X509TrustManager” should point you in the right direction.
In this case a search for “X509TrustManager” returned one class which implements an own Trustmanager. This file contains methods named “checkClientTrusted”, “checkServerTrusted” and “getAcceptedIssuers”.
The “return-void” opcode was added to the first line of each of these methods. The “return-void” statement is a Dalvik opcode to return ‘void’ or null. For more Dalvik opcodes refer to http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html.
In this context, return-void means that no certificate checks are performed and the application will accept all certificates.

![Screenshot showing the inserted opcode.](Images/Chapters/0x06a/patching-sslpinning.jpg)

#### Hooking Java methods with Xposed

Xposed is a ["framework for modules that can change the behavior of the system and apps without touching any APKs:""](http://repo.xposed.info/module/de.robv.android.xposed.installer). Technically, it is an extended version of Zygote that exports APIs for running Java code when a new process is started. By running Java code in the context of the newly instantiated app, it is possible to resolve, hook and override Java methods belonging to the app. Xposed uses [reflection](https://docs.oracle.com/javase/tutorial/reflect/) to examine and modify the running app. Changes are applied in memory and persist only during the runtime of the process - no patches to the application files are made.

To use Xposed, you first need to install the Xposed framework on a rooted device. Modifications are then deployed in the form of separate apps ("modules") that can be toggled on and off in the Xposed GUI.

##### Example: Bypassing Root Detection

Let's assume you're testing an app that is stubbornly quitting on your rooted device. You decompile the app and find the following highly suspect method:

~~~

package com.example.a.b

public static boolean c() {
  int v3 = 0;
  boolean v0 = false;

  String[] v1 = new String[]{"/sbin/", "/system/bin/", "/system/xbin/", "/data/local/xbin/",
    "/data/local/bin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/"};

    int v2 = v1.length;

    for(int v3 = 0; v3 < v2; v3++) {
      if(new File(String.valueOf(v1[v3]) + "su").exists()) {
         v0 = true;M
         return v0;
      }
    }

    return v0;
}
~~~

This method iterates through a list of directories, and returns "true" (device rooted) if the "su" binary is found in any of them. Checks like this are easy to deactivate - all we have to do is to replace the code with something that returns "false".

Using an Xposed module is one way to do this. Modules for Xposed are developed and deployed with Android Studio just like regular Android apps. The author, rovo89, provides a great [tutorial](https://github.com/rovo89/XposedBridge/wiki/Development-tutorial) showing how to write, compile and install a module.

Code:

~~~

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

~~~

#### Code Injection with FRIDA

Here are some more APIs FRIDA offers on Android:

-	Instantiate Java objects and call static and non-static class methods;
-	Replace Java method implementations;
-	Enumerate live instances of specific classes by scanning the Java heap (Dalvik only);
-	Scan process memory for occurrences of a string;
-	Intercept native function calls to run your own code at function entry and exit.

Some features unfortunately don’t work yet on current Android devices platforms. Most notably, the FRIDA Stalker - a code tracing engine based on dynamic recompilation - does not support ARM at the time of this writing (version 7.2.0). Also, support for ART has been included only recently, so the Dalvik runtime is still better supported.

##### Example: Bypassing Native Debugger Detection

~~~
#v0.1
 
import frida
import sys
 
session = frida.get_remote_device().attach("com.example.targetapp")
 
script = session.create_script("""
 
var funcPtr = Module.findExportByName("libdvm.so", "_Z25dvmDbgIsDebuggerConnectedv");
Interceptor.replace(funcPtr, new NativeCallback(function (pathPtr, flags) {
    return 0;
}, 'int', []));
 
def on_message(message, data):
    print(message)
 
script.on('message', on_message)
script.load()
sys.stdin.read()
~~~

### Reverse Engineering on Android

#### Statically Analyzing Java Code

TODO: Pulling APK File from the device

TODO: DEX vs. OAT

#### Statically Analyzing Native Code

#### Debugging Android Apps

#### Execution Tracing

The JDB command line tool offers basic execution tracing functionality.
To trace an app right from the start we can pause the app using the Android “Wait for Debugger” feature or a kill –STOP command and attach JDB to set a deferred method breakpoint on an initialization method of our choice. Once the breakpoint hits, we activate method tracing with the trace go methods command and resume execution. JDB will dump all method entries and exits from that point on.

~~~~
Pyramidal-Neuron:DIGIPASS berndt$ adb forward tcp:7777 jdwp:7288
Pyramidal-Neuron:DIGIPASS berndt$ { echo "suspend"; cat; } | jdb -attach localhost:7777
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
~~~~

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

~~~~
while true; do pid=$(pgrep 'target_process' | head -1); if [[ -n "$pid" ]]; then strace -s 2000 - e “!read” -ff -p "$pid"; break; fi; done
~~~~

##### Ftrace

Ftrace is a tracing utility built directly into the Linux kernel. On a rooted device, ftrace can be used to trace kernel system calls in a more transparent way than is possible with strace, which relies on the ptrace system call to attach to the target process.
Conveniently, ftrace functionality is found in the stock Android kernel on both Lollipop and Marshmallow. It can be enabled with the following command:

~~~~
echo 1 > /proc/sys/kernel/ftrace_enabled
~~~~

The /sys/kernel/debug/tracing directory holds all control and output files and related to ftrace. The following files are found in this directory:

- available_tracers: This file lists the available tracers compiled into the kernel.
- current_tracer: This file is used to set or display the current tracer.
- tracing_on: Echo 1 into this file to allow/start update of the ring buffer. Echoing 0 will prevent further writes into the ring buffer.

##### KProbes

The KProbes interface provides us with an even more powerful way to instrument the kernel: It allows us to insert probes into (almost) arbitrary code addresses within kernel memory. Kprobes work by inserting a breakpoint instruction at the specified address. Once the breakpoint is hit, control passes to the Kprobes system, which then executes the handler function(s) defined by the user as well as the original instruction. Besides being great for function tracing, KProbes can be used to implement rootkit-like functionality such as file hiding.

Jprobes and Kretprobes are additional probe types based on Kprobes that allow hooking of function entries and exits.

Unfortunately, the stock Android kernel comes without loadable module support, which is a problem given that Kprobes are usually deployed as kernel modules. Another issue is that the Android kernel is compiled with strict memory protection which prevents patching some parts of Kernel memory. Using Elfmaster’s system call hooking method (5) results in a Kernel panic on default Lolllipop and Marshmallow due to sys_call_table being non-writable. We can however use Kprobes on a sandbox by compiling our own, more lenient Kernel (more on this later).

#### Emulation-based Analysis

Running an app in the emulator gives us powerful ways to monitor and manipulate its environment. For some reverse engineering tasks, especially those that require low-level instruction tracing, emulation is the best (or only) choice.

Even in its standard form that ships with the Android SDK, the Android emulator – a.k.a. “emulator” - is a somewhat capable reverse engineering tool. It is based on QEMU, a generic and open source machine emulator. QEMU emulates a guest CPU by translating the guest instructions on-the-fly into instructions the host processor can understand. Each basic block of guest instructions is disassembled and translated into an intermediate representation called Tiny Code Generator (TCG). The TCG block is compiled into a block of host instructions, stored into a code cache, and executed. After execution of the basic block has completed, QEMU repeats the process for the next block of guest instructions (or loads the already translated block from the cache). The whole process is called dynamic binary translation.

Because the Android emulator is a fork of QEMU, it comes with the full QEMU feature set, including its monitoring, debugging and tracing facilities. QEMU-specific parameters can be passed to the emulator with the -qemu command line flag. We can use QEMU’s built-in tracing facilities to log executed instructions and virtual register values. Simply starting qemu with the "-d" command line flag will cause it to dump the blocks of guest code, micro operations or host instructions being executed. The –d in_asm option logs all basic blocks of guest code as they enter QEMU’s translation function. The following command logs all translated blocks to a file:

```
emulator -show-kernel -avd Nexus_4_API_19 -snapshot default-boot -no-snapshot-save -qemu -d in_asm,cpu 2>/tmp/qemu.log
```

Unfortunately, it is not possible to generate a complete guest instruction trace with QEMU, because code blocks are written to the log only at the time they are translated – not when they’re taken from the cache. For example, if a block is repeatedly executed in a loop, only the first iteration will be printed to the log. There’s no way to disable TB caching in QEMU (save for hacking the source code). Even so, the functionality is sufficient for basic tasks, such as reconstructing the disassembly of a natively executed cryptographic algorithm.

Dynamic analysis frameworks, such as PANDA and DroidScope, build on QEMU to provide more complete tracing functionality. PANDA/PANDROID is your best if you’re going for a CPU-trace based analysis, as it allows you to easily record and replay a full trace, and is relatively easy to set up if you follow the build instructions for Ubuntu.

##### DroidScope

DroidScope is a malware analysis engine based on QEMU. It adds instrumentation on several levels, making it possible to fully reconstruct the semantics on the hardware, Linux and Java level.

DroidScope exports instrumentation APIs that mirror the different context levels (hardware, OS and Java) of a real Android device. Analysis tools can use these APIs to query or set information and register callbacks for various events. For example, a plugin can register callbacks for native instruction start and end, memory reads and writes, register reads and writes, system calls or Java method calls.

All of this makes it possible to build tracers that are practically transparent to the target application (as long as we can hide the fact it is running in an emulator). One limitation is that DroidScope is compatible with the Dalvik VM only.

DroidScope is available as an extension to the DECAF dynamic analysis framework at:

https://github.com/sycurelab/DECAF

##### PANDA

PANDA is another QEMU-based dynamic analysis platform. Similar to DroidScope, PANDA can be extended by registering callbacks that are triggered upon certain QEMU events. The twist PANDA adds is its record/replay feature. This allows for an iterative workflow: The reverse engineer records an execution trace of some the target app (or some part of it) and then replays it over and over again, refining his analysis plugins with each iteration.

PANDA comes with some premade plugins, such as a stringsearch tool and a syscall tracer. Most importantly, it also supports Android guests and some of the DroidScope code has even been ported over. Building and running PANDA for Android (“PANDROID”) is relatively straightforward. To test it, clone Moiyx’s git repository14 and build PANDA as follows:MM

As of this writing, Android versions up to 4.4.1 run fine in PANDROID, but anything newer than that won’t boot. Also, the Java level introspection code only works on the specific Dalvik runtime of Android 2.3. Anyways, older versions of Android seem to run much faster in the emulator, so if you plan on using PANDA sticking with Gingerbread is probably best. For more information, check out the extensive documentation in the PANDA git repo:

https://github.com/moyix/panda/blob/master/docs/

##### VxStripper

Another very useful tool built on QEMU is VxStripper by Sébastien Josse. VXStripper is specifically designed for de-obfuscating binaries. By instrumenting QEMU's dynamic binary translation mechanisms, it dynamically extracts an intermediate representation of a binary. It then applies simplifications to the extracted intermediate representation, and recompiles the simplified binary using LLVM. This is a very powerful way of normalizing obfuscated programs. See Sébastien's paper [Malware Dynamic Recompilation](http://ieeexplore.ieee.org/document/6759227/) for more information.

#### Customizing Android

Working on real device has advantages especially for interactive, debugger-supported static / dynamic analysis. For one, it is simply faster to work on a real device. Also, being run on a real device gives the target app less reason to be suspicious and misbehave. By instrumenting the live environment at strategic points, we can obtain useful tracing functionality and manipulate the environment to help us bypass any anti-tampering defenses the app might implement.

##### Preparing a development environment
To get the development environment ready, simply download Google’s Android Studio. It comes with a SDK Manager app that lets you install the Android SDK tools and manage SDKs for various API levels, as well as the emulator and an AVD Manager application to create emulator images. Android Studio can be downloaded from the Android download page:
https://developer.android.com/develop/index.html
You’ll also need the Android NDK for compiling anything that creates native code. The NDK contains prebuilt toolchains for cross-compiling native code for different architectures. The NDK is available as a separate download:
https://developer.android.com/ndk/downloads/index.html
After you downloaded the SDK, create a standalone toolchain for Android Lollipop (API 21):

~~~~
$ $YOUR_NDK_PATH/build/tools/make-standalone-toolchain.sh --arch=arm --platform=android-21 --install-dir=/tmp/my-android-toolchain
~~~~


##### Customizing the RAMDisk

The initramfs is a small CPIO archive stored inside the boot image. It contains a few files that are required at boot time before the actual root file system is mounted. On Android, the initramfs stays mounted indefinitely, and it contains an important configuration file named default.prop that defines some basic system properties. By making some changes to this file, we can make the Android environment a bit more reverse-engineering-friendly.
For our purposes, the most important settings in default.prop are ro.debuggable and ro.secure.

~~~~
shell@hammerhead:/ $ cat /default.prop                                         
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
~~~~

Setting ro.debuggable to 1 causes all apps running on the system to be debuggable (i.e., the debugger thread runs in every process), independent of the android:debuggable attribute in the app’s Manifest. Setting ro.secure to 0 causes adbd to be run as root.
To modify initrd on any Android device, back up the original boot image using TWRP, or simply dump it with a command like:

~~~~
adb shell cat /dev/mtd/mtd0 >/mnt/sdcard/boot.img
adb pull /mnt/sdcard/boot.img /tmp/boot.img
~~~~

Use the abootimg tool as described in Krzysztof Adamski’s how-to to extract the contents of the boot image:

~~~~
mkdir boot
cd boot
../abootimg -x /tmp/boot.img
mkdir initrd
cd initrd
cat ../initrd.img | gunzip | cpio -vid
~~~~

Take note of the boot parameters written to bootimg.cfg – you will need to these parameters later when booting your new kernel and ramdisk.

~~~~
berndt@osboxes:~/Desktop/abootimg/boot$ cat bootimg.cfg
bootsize = 0x1600000
pagesize = 0x800
kerneladdr = 0x8000
ramdiskaddr = 0x2900000
secondaddr = 0xf00000
tagsaddr = 0x2700000
name =
cmdline = console=ttyHSL0,115200,n8 androidboot.hardware=hammerhead user_debug=31 maxcpus=2 msm_watchdog_v2.enable=1
Modify default.prop and package your new ramdisk:
cd initrd
find . | cpio --create --format='newc' | gzip > ../myinitd.img
~~~~

##### Customizing the Android Kernel

Many operations performed by a process, such as allocating memory and accessing files, rely on services provided by the kernel in the form of system calls. In an ARM environment, system calls are done with the SVC instruction which triggers a software interrupt. This interrupt calls the vector_swi() kernel function, which then uses the system call number as an offset into a table of function pointers. In Android, this table is exported with the symbol name sys_call_table.
System call hooking is a commonly used technique to monitor and manipulating the interface between user mode and kernel mode. Hooks can be installed in different ways, but rewriting the function pointers in sys_call_table is probably the easiest and most straight-forward.
Newer stock Android kernels enforce some restrictions that prevent system call hooking. Specifically, the stock Lollipop and Marshmallow kernels for the Nexus 5 are built with the CONFIG_STRICT_MEMORY_RWX option enabled. This prevents writing to kernel code regions read-only data, which means that any attempts to patch kernel code or sys_call_table result in a segmentation fault and reboot. For the purpose of our sandbox however, we can simply build our own kernel that disables this feature.
Given that we have to compile a custom kernel for our sandbox anyway, we’ll also add a couple more features for added convenience, such as LKM support and the /dev/kmem interface.
To build the Android kernel you need a toolchain (set of programs to cross-compile the sources) as well as the appropriate version of the kernel sources. Instructions on how to identify the correct git repository and branch for a given device and Android version can be found at:

https://source.android.com/source/building-kernels.html#id-version

For example, to get kernel sources for Lollipop that are compatible with the Nexus 5, we need to clone the msm repo and check out one the android-msm-hammerhead branch (hammerhead is the “codename” of the Nexus 5., and yes, finding the right branch is a confusing process). Once the sources are downloaded, create the default kernel config file with the command make hammerhead_defconfig (or whatever_defconfig, depending on your target device).

~~~~
$ git clone https://android.googlesource.com/kernel/msm.git
$ cd msm
$ git checkout origin/android-msm-hammerhead-3.4-lollipop-mr1
$ make hammerhead_defconfig
$ vim .config
~~~~

I recommend using the following settings to enable the most important tracing facilities, add loadable module support, and open up kernel memory for patching.

~~~~
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
~~~~

Once you are finished editing save the .config file and build the kernel.

~~~~
$ export ARCH=arm
$ export SUBARCH=arm
$ export CROSS_COMPILE=/path_to_your_ndk/arm-eabi-4.8/bin/arm-eabi-
$ make
~~~~

If the build process completes successfully, you will find the bootable kernel image at arch/arm/boot/zImage-dtb.

##### Booting the Custom Environment

The fastboot boot command allows you to test your new kernel and ramdisk without actually flashing it (once you’re sure it everything works, you can make the changes permanent with fastboot flash). Restart the device in fastboot mode with the following command:
$ adb reboot bootloader

Then, use the fastboot command to boot Android with the new kernel and ramdisk, passing the boot parameters of the original image:
~~~~
$ fastboot boot zImage-dtb myinitrd.img --base 0 --kernel-offset 0x8000 --ramdisk-offset 0x2900000 --tags-offset 0x2700000 -c "console=ttyHSL0,115200,n8 androidboot.hardware=hammerhead user_debug=31 maxcpus=2 msm_watchdog_v2.enable=1"
~~~~

To quickly verify that the new kernel is running, navigate to Settings->About phone and check the “kernel version” field.

##### Loading Kernel Modules

##### Example: File Hiding
