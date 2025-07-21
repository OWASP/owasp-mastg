---
masvs_category: MASVS-RESILIENCE
platform: android
title: Detection of Reverse Engineering Tools
---

The presence of tools, frameworks and apps commonly used by reverse engineers may indicate an attempt to reverse engineer the app. Some of these tools can only run on a rooted device, while others force the app into debugging mode or depend on starting a background service on the mobile phone. Therefore, there are different ways that an app may implement to detect a reverse engineering attack and react to it, e.g. by terminating itself.

You can detect popular reverse engineering tools that have been installed in an unmodified form by looking for associated application packages, files, processes, or other tool-specific modifications and artifacts. In the following examples, we'll discuss different ways to detect the Frida instrumentation framework, which is used extensively in this guide. Other tools, such as ElleKit and Xposed, can be detected similarly. Note that DBI/injection/hooking tools can often be detected implicitly, through runtime integrity checks, which are discussed below.

For instance, in its default configuration on a rooted device, Frida runs on the device as frida-server. When you explicitly attach to a target app (e.g. via frida-trace or the Frida REPL), Frida injects a frida-agent into the memory of the app. Therefore, you may expect to find it there after attaching to the app (and not before). If you check `/proc/<pid>/maps` you'll find the frida-agent as frida-agent-64.so:

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida
71b6bd6000-71b7d62000 r-xp  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7d7f000-71b7e06000 r--p  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7e06000-71b7e28000 rw-p  /data/local/tmp/re.frida.server/frida-agent-64.so
```

The other method (which also works for non-rooted devices) consists of embedding a [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") into the APK and _forcing_ the app to load it as one of its native libraries. If you inspect the app memory maps after starting the app (no need to attach explicitly to it) you'll find the embedded frida-gadget as libfrida-gadget.so.

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida

71b865a000-71b97f1000 r-xp  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b9802000-71b988a000 r--p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b988a000-71b98ac000 rw-p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
```

Looking at these two _traces_ that Frida _lefts behind_, you might already imagine that detecting those would be a trivial task. And actually, so trivial will be bypassing that detection. But things can get much more complicated. The following table shortly presents a set of some typical Frida detection methods and a short discussion on their effectiveness.

> Some of the following detection methods are presented in the article ["The Jiu-Jitsu of Detecting Frida" by Berdhard Mueller](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida "The Jiu-Jitsu of Detecting Frida") (archived). Please refer to it for more details and for example code snippets.

| Method | Description | Discussion |
| --- | --- | --- |
| **Checking the App Signature** | In order to embed the frida-gadget within the APK, it would need to be repackaged and resigned. You could check the signature of the APK when the app is starting (e.g. [GET_SIGNING_CERTIFICATES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES "GET_SIGNING_CERTIFICATES") since API level 28) and compare it to the one you pinned in your APK. | This is unfortunately too trivial to bypass, e.g. by patching the APK or performing system call hooking. |
| **Check The Environment For Related Artifacts** | Artifacts can be package files, binaries, libraries, processes, and temporary files. For Frida, this could be the frida-server running in the target (rooted) system (the daemon responsible for exposing Frida over TCP). Inspect the running services ([`getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager.html#getRunningServices%28int%29 "getRunningServices")) and processes (`ps`) searching for one whose name is "frida-server". You could also walk through the list of loaded libraries and check for suspicious ones (e.g. those including "frida" in their names). | Since Android 7.0 (API level 24), inspecting the running services/processes won't show you daemons like the frida-server as it is not being started by the app itself. Even if it would be possible, bypassing this would be as easy just renaming the corresponding Frida artifact (frida-server/frida-gadget/frida-agent). |
| **Checking For Open TCP Ports** | The frida-server process binds to TCP port 27042 by default. Check whether this port is open is another method of detecting the daemon. | This method detects frida-server in its default mode, but the listening port can be changed via a command line argument, so bypassing this is a little too trivial. |
| **Checking For Ports Responding To D-Bus Auth** | `frida-server` uses the D-Bus protocol to communicate, so you can expect it to respond to D-Bus AUTH. Send a D-Bus AUTH message to every open port and check for an answer, hoping that `frida-server` will reveal itself. | This is a fairly robust method of detecting `frida-server`, but Frida offers alternative modes of operation that don't require frida-server. |
| **Scanning Process Memory for Known Artifacts** | Scan the memory for artifacts found in Frida's libraries, e.g. the string "LIBFRIDA" present in all versions of frida-gadget and frida-agent. For example, use `Runtime.getRuntime().exec` and iterate through the memory mappings listed in `/proc/self/maps` or `/proc/<pid>/maps` (depending on the Android version) searching for the string. | This method is a bit more effective, and it is difficult to bypass with Frida only, especially if some obfuscation has been added and if multiple artifacts are being scanned. However, the chosen artifacts might be patched in the Frida binaries. Find the source code on [Berdhard Mueller's GitHub](https://github.com/muellerberndt/frida-detection-demo/blob/master/AntiFrida/app/src/main/cpp/native-lib.cpp "frida-detection-demo"). |

Please remember that this table is far from exhaustive. We could start talking about detecting [named pipes](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (used by frida-server for external communication) and [trampolines](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (indirect jump vectors inserted at the prologue of functions), which would help with detecting ElleKit or Frida's Interceptor. Many more techniques exist, and each of them will depend on whether you're using a rooted device, the specific version of the rooting method and/or the version of the tool itself. Further, the app can try to make it harder to detect the implemented protection mechanisms by using various obfuscation techniques. At the end, this is part of the cat and mouse game of protecting data being processed on an untrusted environment (an app running in the user device).

> It is important to note that these controls are only increasing the complexity of the reverse engineering process. If used, the best approach is to combine the controls cleverly instead of using them individually. However, none of them can assure a 100% effectiveness, as the reverse engineer will always have full access to the device and will therefore always win! You also have to consider that integrating some of the controls into your app might increase the complexity of your app and even have an impact on its performance.
