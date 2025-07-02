---
title: Frida
platform: generic
source: https://github.com/frida/frida
---

[Frida](https://www.frida.re "Frida") is a free and open source dynamic code instrumentation toolkit written by Ole André Vadla Ravnås that works by injecting the [QuickJS](https://bellard.org/quickjs/) JavaScript engine (previously [Duktape](https://duktape.org/ "Duktape JavaScript Engine") and [V8](https://v8.dev/docs "V8 JavaScript Engine")) into the instrumented process. Frida lets you execute snippets of JavaScript into native apps on Android and iOS (as well as on [other platforms](https://www.frida.re/docs/home/ "So what is Frida, exactly?")).

<img src="Images/Chapters/0x04/frida_logo.png" style="width: 80%; border-radius: 5px; margin: 2em" />

## Installation

To install Frida locally, simply run:

```bash
pip install frida-tools
```

Or refer to the [installation page](https://www.frida.re/docs/installation/ "Frida Installation") for more details.

## Modes of Operation

Code can be injected in several ways. For example, Xposed permanently modifies the Android app loader, providing hooks for running your own code every time a new process is started.
In contrast, Frida implements code injection by writing code directly into the process memory. When attached to a running app:

- Frida uses ptrace to hijack a thread of a running process. This thread is used to allocate a chunk of memory and populate it with a mini-bootstrapper.
- The bootstrapper starts a fresh thread, connects to the Frida debugging server that's running on the device, and loads a shared library that contains the Frida agent (`frida-agent.so`).
- The agent establishes a bi-directional communication channel back to the tool (e.g. the Frida REPL or your custom Python script).
- The hijacked thread resumes after being restored to its original state, and process execution continues as usual.

<img src="Images/Chapters/0x04/frida.png" width="100%" />

- _Frida Architecture, source: [https://www.frida.re/docs/hacking/](https://www.frida.re/docs/hacking "Frida - Hacking")_

Frida offers three modes of operation:

1. Injected: this is the most common scenario when frida-server is running as a daemon in the iOS or Android device. frida-core is exposed over TCP, listening on localhost:27042 by default. Running in this mode is not possible on devices that are not rooted or jailbroken.
2. Embedded: this is the case when your device is not rooted nor jailbroken (you cannot use ptrace as an unprivileged user), you're responsible for the injection of the [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") library by embedding it into your app, manually or via third-party tools such as @MASTG-TOOL-0038.
3. Preloaded: similar to `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`. You can configure the frida-gadget to run autonomously and load a script from the filesystem (e.g. path relative to where the Gadget binary resides).

## APIs

Independently of the chosen mode, you can make use of the [Frida JavaScript APIs](https://www.frida.re/docs/javascript-api/ "Frida JavaScript APIs") to interact with the running process and its memory. Some of the fundamental APIs are:

- [Interceptor](https://www.frida.re/docs/javascript-api/#interceptor "Interceptor"): When using the Interceptor API, Frida injects a trampoline (aka in-line hooking) at the function prologue which provokes a redirection to our custom code, executes our code, and returns to the original function. Note that while very effective for our purpose, this introduces a considerable overhead (due to the trampoline related jumping and context switching) and cannot be considered transparent as it overwrites the original code and acts similar to a debugger (putting breakpoints) and therefore can be detected in a similar manner, e.g. by applications that periodically checksum their own code.
- [Stalker](https://www.frida.re/docs/javascript-api/#stalker "Stalker"): If your tracing requirements include transparency, performance and high granularity, Stalker should be your API of choice. When tracing code with the Stalker API, Frida leverages just-in-time dynamic recompilation (by using [Capstone](http://www.capstone-engine.org/ "Capstone")): when a thread is about to execute its next instructions, Stalker allocates some memory, copies the original code over, and interlaces the copy with your custom code for instrumentation. Finally, it executes the copy (leaving the original code untouched, and therefore avoiding any anti-debugging checks). This approach increases instrumentation performance considerably and allows for very high granularity when tracing (e.g. by tracing exclusively CALL or RET instructions). You can learn more in-depth details in [the blog post "Anatomy of a code tracer" by Frida's creator Ole](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8 "Anatomy of a code tracer") [#vadla]. Some examples of use for Stalker are, for example [who-does-it-call](https://codeshare.frida.re/@oleavr/who-does-it-call/ "who-does-it-call") or [diff-calls](https://github.com/frida/frida-presentations/blob/master/R2Con2017/01-basics/02-diff-calls.js "diff-calls").
- [Java](https://www.frida.re/docs/javascript-api/#java "Java"): When working on Android you can use this API to enumerate loaded classes, enumerate class loaders, create and use specific class instances, enumerate live instances of classes by scanning the heap, etc.
- [ObjC](https://www.frida.re/docs/javascript-api/#objc "ObjC"): When working on iOS you can use this API to get a mapping of all registered classes, register or use specific class or protocol instances, enumerate live instances of classes by scanning the heap, etc.

### Frida 17

Frida 17 introduces [breaking changes](https://frida.re/news/2025/05/17/frida-17-0-0-released/), such as the removal of the bundled runtime bridges (`frida-{objc,swift,java}-bridge`) within Frida's GumJS runtime. This means you must now explicitly install the bridges you need by using `frida-pm install`:

 ```bash
 frida-pm install frida-java-bridge
 ```

However, the commands `frida` and `frida-trace` come with the Java, Objective-C, and Swift bridges pre-bundled, so you can still use them without manual installation in those contexts. You can learn more about bridges in the [Frida documentation](https://frida.re/docs/bridges/).

Frida has made changes to its native APIs. While these changes may break some of your existing scripts, they encourage you to write more readable and performant code. For instance, now, `Process.enumerateModules()` returns an array of `Module` objects, allowing you to work with them directly.

```js
for (const module of Process.enumerateModules()) {
  console.log(module.name);
}
```

Another API that was removed is `Module.getSymbolByName`, which is used in many scripts. Depending on if you know which module the symbol is located in or not, you can use one of the following two alternatives:

```js
// If you know the module
Process.getModuleByName('libc.so').getExportByName('open')

// If you don't (i.e., the old Module.getSymbolByName(null, 'open'); )
Module.getGlobalExportByName('open');
```

For more details, refer to the [Frida 17.0.0 Release Notes](https://frida.re/news/2025/05/17/frida-17-0-0-released/).

## Tools

Frida also provides a couple of simple tools built on top of the Frida API and available right from your terminal after installing frida-tools via pip. For instance:

- You can use the [Frida CLI](https://www.frida.re/docs/frida-cli/ "Frida CLI") (`frida`) for quick script prototyping and try/error scenarios.
- [`frida-ps`](https://www.frida.re/docs/frida-ps/ "frida-ps") to obtain a list of all apps (or processes) running on the device including their names, identifiers and PIDs.
- [`frida-ls-devices`](https://www.frida.re/docs/frida-ls-devices/ "frida-ls-devices") to list your connected devices running Frida servers or agents.
- [`frida-trace`](https://www.frida.re/docs/frida-trace/ "frida-trace") to quickly trace methods that are part of an iOS app or that are implemented inside an Android native library.

In addition, you'll also find several open source Frida-based tools, such as:

- @MASTG-TOOL-0061: a Runtime Application Instrument toolkig for iOS.
- @MASTG-TOOL-0106: a memory dumping tool for both Android and iOS.
- @MASTG-TOOL-0038: a runtime mobile security assessment framework.
- @MASTG-TOOL-0036: a project merging the powerful reverse engineering capabilities of radare2 with the dynamic instrumentation toolkit of Frida.
- @MASTG-TOOL-0107: a tool for tracing usage of the Android JNI runtime methods by a native library.

We will be using all of these tools throughout the guide.

You can use these tools as-is, tweak them to your needs, or take as excellent examples on how to use the APIs. Having them as an example is very helpful when you write your own hooking scripts or when you build introspection tools to support your reverse engineering workflow.
