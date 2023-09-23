---
masvs_category: MASVS-RESILIENCE
platform: ios
---

# iOS Anti-Reversing Defenses

## Overview

This chapter covers defense-in-depth measures recommended for apps that process, or give access to, sensitive data or functionality. Research shows that [many App Store apps often include these measures](https://seredynski.com/articles/a-security-review-of-1300-appstore-applications.html "A security review of 1,300 AppStore applications - 5 April 2020").

These measures should be applied as needed, based on an assessment of the risks caused by unauthorized tampering with the app and/or reverse engineering of the code.

- Apps must never use these measures as a replacement for security controls, and are therefore expected to fulfill other baseline security measures such as the rest of the MASVS security controls.
- Apps should combine these measures cleverly instead of using them individually. The goal is to discourage reverse engineers from performing further analysis.
- Integrating some of the controls into your app might increase the complexity of your app and even have an impact on its performance.

You can learn more about principles and technical risks of reverse engineering and code modification in these OWASP documents:

- [OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering](https://wiki.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project "OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering")
- [OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification](https://wiki.owasp.org/index.php/Technical_Risks_of_Reverse_Engineering_and_Unauthorized_Code_Modification "OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification")

### General Disclaimer

The **lack of any of these measures does not cause a vulnerability** - instead, they are meant to increase the app's resilience against reverse engineering and specific client-side attacks.

None of these measures can assure a 100% effectiveness, as the reverse engineer will always have full access to the device and will therefore always win (given enough time and resources)!

For example, preventing debugging is virtually impossible. If the app is publicly available, it can be run on an untrusted device that is under full control of the attacker. A very determined attacker will eventually manage to bypass all the app's anti-debugging controls by patching the app binary or by dynamically modifying the app's behavior at runtime with tools such as Frida.

### Jailbreak Detection

Jailbreak detection mechanisms are added to reverse engineering defense to make running the app on a jailbroken device more difficult. This blocks some of the tools and techniques reverse engineers like to use. Like most other types of defense, jailbreak detection is not very effective by itself, but scattering checks throughout the app's source code can improve the effectiveness of the overall anti-tampering scheme.

> You can learn more about Jailbreak/Root Detection in the research study ["Jailbreak/Root Detection Evasion Study on iOS and Android"](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf "Jailbreak/Root Detection Evasion Study on iOS and Android") by Dana Geist and Marat Nigmatullin.

#### Common Jailbreak Detection Checks

Here we present three typical jailbreak detection techniques (more information [in this blog post](https://www.trustwave.com/Resources/SpiderLabs-Blog/Jailbreak-Detection-Methods/ "Jailbreak Detection Methods")):

**File-based Checks:**

The app might be checking for files and directories typically associated with jailbreaks, such as:

```default
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/usr/sbin/frida-server
/usr/bin/cycript
/usr/local/bin/cycript
/usr/lib/libcycript.dylib
/var/log/syslog
```

**Checking File Permissions:**

The app might be trying to write to a location that's outside the application's sandbox. For instance, it may attempt to create a file in, for example, the `/private` directory. If the file is created successfully, the app can assume that the device has been jailbroken.

```swift
do {
    let pathToFileInRestrictedDirectory = "/private/jailbreak.txt"
    try "This is a test.".write(toFile: pathToFileInRestrictedDirectory, atomically: true, encoding: String.Encoding.utf8)
    try FileManager.default.removeItem(atPath: pathToFileInRestrictedDirectory)
    // Device is jailbroken
} catch {
    // Device is not jailbroken
}
```

**Checking Protocol Handlers:**

The app might be attempting to call well-known protocol handlers such as `cydia://` (available by default after installing [Cydia](0x08a-Testing-Tools.md#cydia "Cydia")).

```swift
if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
    // Device is jailbroken
}
```

#### Automated Jailbreak Detection Bypass

The quickest way to bypass common Jailbreak detection mechanisms is [objection](0x08a-Testing-Tools.md#objection). You can find the implementation of the jailbreak bypass in the [jailbreak.ts script](https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts "jailbreak.ts").

#### Manual Jailbreak Detection Bypass

If the automated bypasses aren't effective you need to get your hands dirty and reverse engineer the app binaries until you find the pieces of code responsible for the detection and either patch them statically or apply runtime hooks to disable them.

**Step 1: Reverse Engineering:**

When you need to reverse engineer a binary looking for jailbreak detection, the most obvious way is to search for known strings, such as "jail" or "jailbreak". Note that this won't be always effective, especially when resilience measures are in place or simply when the the developer has avoided such obvious terms.

Example: Download the [Damn Vulnerable iOS application (DVIA-v2)](0x08b-Reference-Apps.md#dvia-v2), unzip it, load the main binary into [radare2](0x08a-Testing-Tools.md#radare2) and wait for the analysis to complete.

```sh
r2 -A ./DVIA-v2-swift/Payload/DVIA-v2.app/DVIA-v2
```

Now you can list the binary's symbols using the `is` command and apply a case-insensitive grep (`~+`) for the string "jail".

```sh
[0x1001a9790]> is~+jail
...
2230  0x001949a8 0x1001949a8 GLOBAL FUNC 0        DVIA_v2.JailbreakDetectionViewController.isJailbroken.allocator__Bool
7792  0x0016d2d8 0x10016d2d8 LOCAL  FUNC 0        +[JailbreakDetection isJailbroken]
...
```

As you can see, there's an instance method with the signature `-[JailbreakDetectionVC isJailbroken]`.

**Step 2: Dynamic Hooks:**

Now you can use Frida to bypass jailbreak detection by performing the so-called early instrumentation, that is, by replacing function implementation right at startup.

Use `frida-trace` on your host computer:

```bash
frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]"
```

This will start the app, trace calls to `-[JailbreakDetectionVC isJailbroken]`, and create a JavaScript hook for each matching element.
Open `./__handlers__/__JailbreakDetectionVC_isJailbroken_.js` with your favouritte editor and edit the `onLeave` callback function. You can simply replace the return value using `retval.replace()` to always return `0`:

```javascript
onLeave: function (log, retval, state) {
    console.log("Function [JailbreakDetectionVC isJailbroken] originally returned:"+ retval);
    retval.replace(0);  
    console.log("Changing the return value to:"+retval);
}
```

This will provide the following output:

```bash
$ frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]:"

Instrumenting functions...                                           `...
-[JailbreakDetectionVC isJailbroken]: Loaded handler at "./__handlers__/__JailbreakDetectionVC_isJailbroken_.js"
Started tracing 1 function. Press Ctrl+C to stop.

Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
```

### Anti-Debugging Detection

Exploring applications using a debugger is a very powerful technique during reversing. You can not only track variables containing sensitive data and modify the control flow of the application, but also read and modify memory and registers.

There are several anti-debugging techniques applicable to iOS which can be categorized as preventive or as reactive. When properly distributed throughout the app, these techniques act as a supportive measure to increase the overall resilience.

- Preventive techniques act as a first line of defense to impede the debugger from attaching to the application at all.
- Reactive techniques allow the application to detect the presence of a debugger and have a chance to diverge from normal behavior.

#### Using ptrace

As seen in chapter ["Tampering and Reverse Engineering on iOS"](0x06c-Reverse-Engineering-and-Tampering.md#debugging), the iOS XNU kernel implements a `ptrace` system call that's lacking most of the functionality required to properly debug a process (e.g. it allows attaching/stepping but not read/write of memory and registers).

Nevertheless, the iOS implementation of the `ptrace` syscall contains a nonstandard and very useful feature: preventing the debugging of processes. This feature is implemented as the `PT_DENY_ATTACH` request, as described in the [official BSD System Calls Manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html "PTRACE(2)"). In simple words, it ensures that no other debugger can attach to the calling process; if a debugger attempts to attach, the process will terminate. Using `PT_DENY_ATTACH` is a fairly well-known anti-debugging technique, so you may encounter it often during iOS pentests.

> Before diving into the details, it is important to know that `ptrace` is not part of the public iOS API. Non-public APIs are prohibited, and the App Store may reject apps that include them. Because of this, `ptrace` is not directly called in the code; it's called when a `ptrace` function pointer is obtained via `dlsym`.

The following is an example implementation of the above logic:

```objectivec
#import <dlfcn.h>
#import <sys/types.h>
#import <stdio.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
void anti_debug() {
  ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
  ptrace_ptr(31, 0, 0, 0); // PTRACE_DENY_ATTACH = 31
}
```

**Bypass:** To demonstrate how to bypass this technique we'll use an example of a disassembled binary that implements this approach:

<img src="Images/Chapters/0x06j/ptraceDisassembly.png" width="100%" />

Let's break down what's happening in the binary. `dlsym` is called with `ptrace` as the second argument (register R1). The return value in register R0 is moved to register R6 at offset 0x1908A. At offset 0x19098, the pointer value in register R6 is called using the BLX R6 instruction. To disable the `ptrace` call, we need to replace the instruction `BLX R6` (`0xB0 0x47` in Little Endian) with the `NOP` (`0x00 0xBF` in Little Endian) instruction. After patching, the code will be similar to the following:

<img src="Images/Chapters/0x06j/ptracePatched.png" width="100%" />

[Armconverter.com](http://armconverter.com/ "Armconverter") is a handy tool for conversion between bytecode and instruction mnemonics.

Bypasses for other ptrace-based anti-debugging techniques can be found in ["Defeating Anti-Debug Techniques: macOS ptrace variants" by Alexander O'Mara](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/ "Defeating Anti-Debug Techniques: macOS ptrace variants").

#### Using sysctl

Another approach to detecting a debugger that's attached to the calling process involves `sysctl`. According to the Apple documentation, it allows processes to set system information (if having the appropriate privileges) or simply to retrieve system information (such as whether or not the process is being debugged). However, note that just the fact that an app uses `sysctl` might be an indicator of anti-debugging controls, though this [won't be always be the case](http://www.cocoawithlove.com/blog/2016/03/08/swift-wrapper-for-sysctl.html "Gathering system information in Swift with sysctl").

The [Apple Documentation Archive](https://developer.apple.com/library/content/qa/qa1361/_index.html "How do I determine if I\'m being run under the debugger?") includes an example which checks the `info.kp_proc.p_flag` flag returned by the call to `sysctl` with the appropriate parameters. According to Apple, you **shouldn't use this code** unless [it's for the debug build of your program](https://developer.apple.com/library/archive/qa/qa1361/_index.html "Detecting the Debugger").

**Bypass:** One way to bypass this check is by patching the binary. When the code above is compiled, the disassembled version of the second half of the code is similar to the following:

<img src="Images/Chapters/0x06j/sysctlOriginal.png" width="100%" />

After the instruction at offset 0xC13C, `MOVNE R0, #1` is patched and changed to `MOVNE R0, #0` (0x00 0x20 in in bytecode), the patched code is similar to the following:

<img src="Images/Chapters/0x06j/sysctlPatched.png" width="100%" />

You can also bypass a `sysctl` check by using the debugger itself and setting a breakpoint at the call to `sysctl`. This approach is demonstrated in [iOS Anti-Debugging Protections #2](https://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/ "iOS Anti-Debugging Protections #2").

#### Using getppid

Applications on iOS can detect if they have been started by a debugger by checking their parent PID. Normally, an application is started by the [launchd](http://newosxbook.com/articles/Ch07.pdf) process, which is the first process running in the _user mode_ and has PID=1. However, if a debugger starts an application, we can observe that `getppid` returns a PID different than `1`. This detection technique can be implemented in native code (via syscalls), using Objective-C or Swift as shown here:

```default
func AmIBeingDebugged() -> Bool {
    return getppid() != 1
}
```

**Bypass:** Similarly to the other techniques, this has also a trivial bypass (e.g. by patching the binary or by using Frida hooks).

### File Integrity Checks

There are two common approaches to check file integrity: using application source code integrity checks and using file storage integrity checks.

#### Application Source Code Integrity Checks

In the ["Tampering and Reverse Engineering on iOS"](0x06c-Reverse-Engineering-and-Tampering.md#debugging) chapter, we discussed the iOS IPA application signature check. We also saw that determined reverse engineers can bypass this check by re-packaging and re-signing an app using a developer or enterprise certificate. One way to make this harder is to add a custom check that determines whether the signatures still match at runtime.

Apple takes care of integrity checks with DRM. However, additional controls (such as in the example below) are possible. The `mach_header` is parsed to calculate the start of the instruction data, which is used to generate the signature. Next, the signature is compared to the given signature. Make sure that the generated signature is stored or coded somewhere else.

```c
int xyz(char *dst) {
    const struct mach_header * header;
    Dl_info dlinfo;

    if (dladdr(xyz, &dlinfo) == 0 || dlinfo.dli_fbase == NULL) {
        NSLog(@" Error: Could not resolve symbol xyz");
        [NSThread exit];
    }

    while(1) {

        header = dlinfo.dli_fbase;  // Pointer on the Mach-O header
        struct load_command * cmd = (struct load_command *)(header + 1); // First load command
        // Now iterate through load command
        //to find __text section of __TEXT segment
        for (uint32_t i = 0; cmd != NULL && i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT) {
                // __TEXT load command is a LC_SEGMENT load command
                struct segment_command * segment = (struct segment_command *)cmd;
                if (!strcmp(segment->segname, "__TEXT")) {
                    // Stop on __TEXT segment load command and go through sections
                    // to find __text section
                    struct section * section = (struct section *)(segment + 1);
                    for (uint32_t j = 0; section != NULL && j < segment->nsects; j++) {
                        if (!strcmp(section->sectname, "__text"))
                            break; //Stop on __text section load command
                        section = (struct section *)(section + 1);
                    }
                    // Get here the __text section address, the __text section size
                    // and the virtual memory address so we can calculate
                    // a pointer on the __text section
                    uint32_t * textSectionAddr = (uint32_t *)section->addr;
                    uint32_t textSectionSize = section->size;
                    uint32_t * vmaddr = segment->vmaddr;
                    char * textSectionPtr = (char *)((int)header + (int)textSectionAddr - (int)vmaddr);
                    // Calculate the signature of the data,
                    // store the result in a string
                    // and compare to the original one
                    unsigned char digest[CC_MD5_DIGEST_LENGTH];
                    CC_MD5(textSectionPtr, textSectionSize, digest);     // calculate the signature
                    for (int i = 0; i < sizeof(digest); i++)             // fill signature
                        sprintf(dst + (2 * i), "%02x", digest[i]);

                    // return strcmp(originalSignature, signature) == 0;    // verify signatures match

                    return 0;
                }
            }
            cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        }
    }

}
```

**Bypass:**

1. Patch the anti-debugging functionality and disable the unwanted behavior by overwriting the associated code with NOP instructions.
2. Patch any stored hash that's used to evaluate the integrity of the code.
3. Use Frida to hook file system APIs and return a handle to the original file instead of the modified file.

#### File Storage Integrity Checks

Apps might choose to ensure the integrity of the application storage itself, by creating an HMAC or signature over either a given key-value pair or a file stored on the device, e.g. in the Keychain, `UserDefaults`/`NSUserDefaults`, or any database.

For example, an app might contain the following code to generate an HMAC with `CommonCrypto`:

```objectivec
    // Allocate a buffer to hold the digest and perform the digest.
    NSMutableData* actualData = [getData];
    //get the key from the keychain
    NSData* key = [getKey];
    NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
    [actualData appendData: digestBuffer];
```

This script performs the following steps:

1. Get the data as `NSMutableData`.
2. Get the data key (typically from the Keychain).
3. Calculate the hash value.
4. Append the hash value to the actual data.
5. Store the results of step 4.

After that, it might be verifying the HMACs by doing the following:

```objectivec
  NSData* hmac = [data subdataWithRange:NSMakeRange(data.length - CC_SHA256_DIGEST_LENGTH, CC_SHA256_DIGEST_LENGTH)];
  NSData* actualData = [data subdataWithRange:NSMakeRange(0, (data.length - hmac.length))];
  NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
  return [hmac isEqual: digestBuffer];
```

1. Extracts the message and the hmacbytes as separate `NSData`.
2. Repeats steps 1-3 of the procedure for generating an HMAC on the `NSData`.
3. Compares the extracted HMAC bytes to the result of step 1.

Note: if the app also encrypts files, make sure that it encrypts and then calculates the HMAC as described in [Authenticated Encryption](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm").

**Bypass:**

1. Retrieve the data from the device, as described in the ["Device Binding"](#device-binding) section.
2. Alter the retrieved data and return it to storage.

### Reverse Engineering Tools Detection

The presence of tools, frameworks and apps commonly used by reverse engineers may indicate an attempt to reverse engineer the app. Some of these tools can only run on a jailbroken device, while others force the app into debugging mode or depend on starting a background service on the mobile phone. Therefore, there are different ways that an app may implement to detect a reverse engineering attack and react to it, e.g. by terminating itself.

You can detect popular reverse engineering tools that have been installed in an unmodified form by looking for associated application packages, files, processes, or other tool-specific modifications and artifacts. In the following examples, we'll discuss different ways to detect the Frida instrumentation framework, which is used extensively in this guide and also in the real world. Other tools, such as Cydia Substrate or Cycript, can be detected similarly. Note that injection, hooking and DBI (Dynamic Binary Instrumentation) tools can often be detected implicitly, through runtime integrity checks, which are discussed below.

**Bypass:**

The following steps should guide you when bypassing detection of reverse engineering tools:

1. Patch the anti reverse engineering functionality. Disable the unwanted behavior by patching the binary through usage of radare2/[iaito](https://github.com/radareorg/iaito "iaito") or Ghidra.
2. Use Frida or Cydia Substrate to hook file system APIs on the Objective-C/Swift or native layers. Return a handle to the original file, not the modified file.

Refer to the chapter ["Tampering and Reverse Engineering on iOS"](0x06c-Reverse-Engineering-and-Tampering.md) for examples of patching and code injection.

#### Frida Detection

Frida runs under the name of frida-server in its default configuration (injected mode) on a jailbroken device. When you explicitly attach to a target app (e.g. via frida-trace or the Frida CLI), Frida injects a frida-agent into the memory of the app. Therefore, you may expect to find it there after attaching to the app (and not before). On Android, verifying this is pretty straightforward as you can simply grep for the string "frida" in the memory maps of the process ID in the `proc` directory (`/proc/<pid>/maps`).
However, on iOS the `proc` directory is not available, but you can list the loaded dynamic libraries in an app with the function `_dyld_image_count`.

Frida may also run in the so-called embedded mode, which also works for non-jailbroken devices. It consists of embedding a [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") into the IPA and _forcing_ the app to load it as one of its native libraries.

The application's static content, including its ARM-compiled binary and its external libraries, is stored inside the `<Application>.app` directory. If you inspect the content of the `/var/containers/Bundle/Application/<UUID>/<Application>.app` directory, you'll find the embedded frida-gadget as FridaGadget.dylib.

```bash
iPhone:/var/containers/Bundle/Application/AC5DC1FD-3420-42F3-8CB5-E9D77C4B287A/SwiftSecurity.app/Frameworks root# ls -alh
total 87M
drwxr-xr-x 10 _installd _installd  320 Nov 19 06:08 ./
drwxr-xr-x 11 _installd _installd  352 Nov 19 06:08 ../
-rw-r--r--  1 _installd _installd  70M Nov 16 06:37 FridaGadget.dylib
-rw-r--r--  1 _installd _installd 3.8M Nov 16 06:37 libswiftCore.dylib
-rw-r--r--  1 _installd _installd  71K Nov 16 06:37 libswiftCoreFoundation.dylib
-rw-r--r--  1 _installd _installd 136K Nov 16 06:38 libswiftCoreGraphics.dylib
-rw-r--r--  1 _installd _installd  99K Nov 16 06:37 libswiftDarwin.dylib
-rw-r--r--  1 _installd _installd 189K Nov 16 06:37 libswiftDispatch.dylib
-rw-r--r--  1 _installd _installd 1.9M Nov 16 06:38 libswiftFoundation.dylib
-rw-r--r--  1 _installd _installd  76K Nov 16 06:37 libswiftObjectiveC.dylib
```

Looking at these _traces_ that Frida _leaves behind_, you might already imagine that detecting Frida would be a trivial task. And while it is trivial to detect these libraries, it is equally trivial to bypass such a detection. Detection of tools is a cat and mouse game and things can get much more complicated. The following table shortly presents a set of some typical Frida detection methods and a short discussion on their effectiveness.

<div style="page-break-after: always;">
</div>

> Some of the following detection methods are implemented in the [iOS Security Suite](https://github.com/securing/IOSSecuritySuite "iOS Security Suite").

| Method | Description | Discussion |
| --- | --- | --- |
| **Check The Environment For Related Artifacts**  | Artifacts can be packaged files, binaries, libraries, processes, and temporary files. For Frida, this could be the frida-server running in the target (jailbroken) system (the daemon responsible for exposing Frida over TCP) or the frida libraries loaded by the app. | Inspecting running services is not possible for an iOS app on a non-jailbroken device. The Swift method [CommandLine](https://developer.apple.com/documentation/swift/commandline "CommandLine") is not available on iOS to query for information about running processes, but there are unofficial ways, such as by using [NSTask](https://stackoverflow.com/a/56619466 "How can I run Command Line commands or tasks with Swift in iOS?"). Nevertheless when using this method, the app will be rejected during the App Store review process. There is no other public API available to query for running processes or execute system commands within an iOS App. Even if it would be possible, bypassing this would be as easy as just renaming the corresponding Frida artifact (frida-server/frida-gadget/frida-agent). Another way to detect Frida, would be to walk through the list of loaded libraries and check for suspicious ones (e.g. those including "frida" in their names), which can be done by using `_dyld_get_image_name`.
| **Checking For Open TCP Ports** | The frida-server process binds to TCP port 27042 by default. Testing whether this port is open is another method of detecting the daemon. | This method detects frida-server in its default mode, but the listening port can be changed via a command line argument, so bypassing this is very trivial. |
| **Checking For Ports Responding To D-Bus Auth** | `frida-server` uses the D-Bus protocol to communicate, so you can expect it to respond to D-Bus AUTH. Send a D-Bus AUTH message to every open port and check for an answer, hoping that `frida-server` will reveal itself. | This is a fairly robust method of detecting `frida-server`, but Frida offers alternative modes of operation that don't require frida-server. |

Please remember that this table is far from exhaustive. For example, two other possible detection mechanisms are:

- [named pipes](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (used by frida-server for external communication), or
- detecting [trampolines](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (see ["Prevent bypassing of SSL certificate pinning in iOS applications"](https://www.guardsquare.com/en/blog/iOS-SSL-certificate-pinning-bypassing "Prevent bypassing of SSL certificate pinning in iOS applications") for further explanation and sample code for detection of trampolines in an iOS app)

Both would _help_ to detect Substrate or Frida's Interceptor but, for example, won't be effective against Frida's Stalker. Remember that the success of each of these detection methods will depend on whether you're using a jailbroken device, the specific version of the jailbreak and method and/or the version of the tool itself. At the end, this is part of the cat and mouse game of protecting data being processed on an uncontrolled environment (the end user's device).

### Emulator Detection

The goal of emulator detection is to increase the difficulty of running the app on an emulated device. This forces the reverse engineer to defeat the emulator checks or utilize the physical device, thereby barring the access required for large-scale device analysis.

As discussed in the section [Testing on the iOS Simulator](0x06b-Basic-Security-Testing.md#testing-on-the-ios-simulator "Testing on the iOS Simulator") in the basic security testing chapter, the only available simulator is the one that ships with Xcode. Simulator binaries are compiled to x86 code instead of ARM code and apps compiled for a real device (ARM architecture) don't run in the simulator, hence _simulation_ protection was not so much a concern regarding iOS apps in contrast to Android with a wide range of _emulation_ choices available.

However, since its release, [Corellium](https://www.corellium.com/) (commercial tool) has enabled real emulation, [setting itself apart from the iOS simulator](https://www.corellium.com/compare/ios-simulator "Corellium vs Apple\'s iOS Simulator"). In addition to that, being a SaaS solution, Corellium enables large-scale device analysis with the limiting factor just being available funds.

With Apple Silicon (ARM) hardware widely available, traditional checks for the presence of x86 / x64 architecture might not suffice. One potential detection strategy is to identify features and limitations available for commonly used emulation solutions. For instance, Corellium doesn't support iCloud, cellular services, camera, NFC, Bluetooth, App Store access or GPU hardware emulation ([Metal](https://developer.apple.com/documentation/metal/gpu_devices_and_work_submission/getting_the_default_gpu "Apple Metal Framework")). Therefore, smartly combining checks involving any of these features could be an indicator for the presence of an emulated environment.

Pairing these results with the ones from 3rd party frameworks such as [iOS Security Suite](https://github.com/securing/IOSSecuritySuite#emulator-detector-module), [Trusteer](https://www.ibm.com/products/trusteer-mobile-sdk/details) or a no-code solution such as [Appdome](https://www.appdome.com/) (commercial solution) will provide a good line of defense against attacks utilizing emulators.

### Obfuscation

The chapter ["Mobile App Tampering and Reverse Engineering"](0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) introduces several well-known obfuscation techniques that can be used in mobile apps in general.

#### Name Obfuscation

The standard compiler generates binary symbols based on class and function names from the source code. Therefore, if no obfuscation was applied, symbol names remain meaningful and can be easily read straight from the app binary. For instance, a function which detects a jailbreak can be located by searching for relevant keywords (e.g. "jailbreak"). The listing below shows the disassembled function `JailbreakDetectionViewController.jailbreakTest4Tapped` from the [Damn Vulnerable iOS App (DVIA-v2)](0x08b-Reference-Apps.md#dvia-v2).

```assembly
__T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

After the obfuscation we can observe that the symbol’s name is no longer meaningful as shown on the listing below.

```assembly
__T07DVIA_v232zNNtWKQptikYUBNBgfFVMjSkvRdhhnbyyFySbyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

Nevertheless, this only applies to the names of functions, classes and fields. The actual code remains unmodified, so an attacker can still read the disassembled version of the function and try to understand its purpose (e.g. to retrieve the logic of a security algorithm).

#### Instruction Substitution

This technique replaces standard binary operators like addition or subtraction with more complex representations. For example an addition `x = a + b` can be represented as `x = -(-a) - (-b)`. However, using the same replacement representation could be easily reversed, so it is recommended to add multiple substitution techniques for a single case and introduce a random factor. This technique is vulnerable to deobfuscation, but depending on the complexity and depth of the substitutions, applying it can still be time consuming.

#### Control Flow Flattening

Control flow flattening replaces original code with a more complex representation. The transformation breaks the body of a function into basic blocks and puts them all inside a single infinite loop with a switch statement that controls the program flow. This makes the program flow significantly harder to follow because it removes the natural conditional constructs that usually make the code easier to read.

<img src="Images/Chapters/0x06j/control-flow-flattening.png" width="600px">

The image shows how control flow flattening alters code. See ["Obfuscating C++ programs via control flow flattening"](http://ac.inf.elte.hu/Vol_030_2009/003.pdf) for more information.

#### Dead Code Injection

This technique makes the program's control flow more complex by injecting dead code into the program. Dead code is a stub of code that doesn’t affect the original program’s behaviour but increases the overhead for the reverse engineering process.

#### String Encryption

Applications are often compiled with hardcoded keys, licences, tokens and endpoint URLs. By default, all of them are stored in plaintext in the data section of an application’s binary. This technique encrypts these values and injects stubs of code into the program that will decrypt that data before it is used by the program.

#### Recommended Tools

- [SwiftShield](0x08a-Testing-Tools.md#swiftshield) can be used to perform name obfuscation. It reads the source code of the Xcode project and replaces all names of classes, methods and fields with random values before the compiler is used.
- [obfuscator-llvm](https://github.com/obfuscator-llvm) operates on the Intermediate Representation (IR) instead of the source code. It can be used for symbol obfuscation, string encryption and control flow flattening. Since it's based on IR, it can hide out significantly more information about the application as compared to SwiftShield.

Learn more about iOS obfuscation techniques in the paper ["Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience"](https://faculty.ist.psu.edu/wu/papers/obf-ii.pdf "Paper - Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience").

### Device Binding

The purpose of device binding is to impede an attacker who tries to copy an app and its state from device A to device B and continue the execution of the app on device B. After device A has been determined trusted, it may have more privileges than device B. This situation shouldn't change when an app is copied from device A to device B.

[Since iOS 7.0](https://developer.apple.com/library/content/releasenotes/General/RN-iOSSDK-7.0/index.html "iOS 7 release notes"), hardware identifiers (such as MAC addresses) are off-limits but there are other methods for implementing device binding in iOS:

- **`identifierForVendor`**: You can use `[[UIDevice currentDevice] identifierForVendor]` (in Objective-C),  `UIDevice.current.identifierForVendor?.uuidString` (in Swift3), or `UIDevice.currentDevice().identifierForVendor?.UUIDString` (in Swift2). The value of `identifierForVendor` may not be the same if you reinstall the app after other apps from the same vendor are installed and it may change when you update your app bundle's name. Therefore it is best to combine it with something in the Keychain.
- **Using the Keychain**: You can store something in the Keychain to identify the application's instance. To make sure that this data is not backed up, use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (if you want to secure the data and properly enforce a passcode or Touch ID requirement), `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, or `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- **Using Google Instance ID**: see the [implementation for iOS here](https://developers.google.com/instance-id/guides/ios-implementation "iOS implementation Google Instance ID").

Any scheme based on these methods will be more secure the moment a passcode and/or Touch ID is enabled, the materials stored in the Keychain or filesystem are protected with protection classes (such as `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and the `SecAccessControlCreateFlags` is set either with `kSecAccessControlDevicePasscode` (for passcodes), `kSecAccessControlUserPresence` (passcode, Face ID or Touch ID), `kSecAccessControlBiometryAny` (Face ID or Touch ID) or `kSecAccessControlBiometryCurrentSet` (Face ID / Touch ID: but current enrolled biometrics only).
