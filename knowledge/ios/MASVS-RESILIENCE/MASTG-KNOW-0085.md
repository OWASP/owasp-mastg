---
masvs_category: MASVS-RESILIENCE
platform: ios
title: Anti-Debugging Detection
---

Exploring applications using a debugger is a very powerful technique during reversing. You can not only track variables containing sensitive data and modify the control flow of the application, but also read and modify memory and registers.

There are several anti-debugging techniques applicable to iOS which can be categorized as preventive or as reactive. When properly distributed throughout the app, these techniques act as a supportive measure to increase the overall resilience.

- Preventive techniques act as a first line of defense to impede the debugger from attaching to the application at all.
- Reactive techniques allow the application to detect the presence of a debugger and have a chance to diverge from normal behavior.

## Using ptrace

As seen in @MASTG-TECH-0084, the iOS XNU kernel implements a `ptrace` system call that's lacking most of the functionality required to properly debug a process (e.g. it allows attaching/stepping but not read/write of memory and registers).

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

## Using sysctl

Another approach to detecting a debugger that's attached to the calling process involves `sysctl`. According to the Apple documentation, it allows processes to set system information (if having the appropriate privileges) or simply to retrieve system information (such as whether or not the process is being debugged). However, note that just the fact that an app uses `sysctl` might be an indicator of anti-debugging controls, though this [won't be always be the case](http://www.cocoawithlove.com/blog/2016/03/08/swift-wrapper-for-sysctl.html "Gathering system information in Swift with sysctl").

The [Apple Documentation Archive](https://developer.apple.com/library/content/qa/qa1361/_index.html "How do I determine if I\'m being run under the debugger?") includes an example which checks the `info.kp_proc.p_flag` flag returned by the call to `sysctl` with the appropriate parameters. According to Apple, you **shouldn't use this code** unless [it's for the debug build of your program](https://developer.apple.com/library/archive/qa/qa1361/_index.html "Detecting the Debugger").

**Bypass:** One way to bypass this check is by patching the binary. When the code above is compiled, the disassembled version of the second half of the code is similar to the following:

<img src="Images/Chapters/0x06j/sysctlOriginal.png" width="100%" />

After the instruction at offset 0xC13C, `MOVNE R0, #1` is patched and changed to `MOVNE R0, #0` (0x00 0x20 in in bytecode), the patched code is similar to the following:

<img src="Images/Chapters/0x06j/sysctlPatched.png" width="100%" />

You can also bypass a `sysctl` check by using the debugger itself and setting a breakpoint at the call to `sysctl`. This approach is demonstrated in [iOS Anti-Debugging Protections #2](https://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/ "iOS Anti-Debugging Protections #2").

## Using getppid

Applications on iOS can detect if they have been started by a debugger by checking their parent PID. Normally, an application is started by the [launchd](http://newosxbook.com/articles/Ch07.pdf) process, which is the first process running in the _user mode_ and has PID=1. However, if a debugger starts an application, we can observe that `getppid` returns a PID different than `1`. This detection technique can be implemented in native code (via syscalls), using Objective-C or Swift as shown here:

```default
func AmIBeingDebugged() -> Bool {
    return getppid() != 1
}
```

**Bypass:** Similarly to the other techniques, this has also a trivial bypass (e.g. by patching the binary or by using Frida hooks).
