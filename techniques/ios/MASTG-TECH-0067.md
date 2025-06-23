---
title: Dynamic Analysis on iOS
platform: ios
---

Jailbreaking a device simplifies many aspects of dynamic analysis. It provides privileged access and removes code signing restrictions, enabling the use of more powerful tools and techniques. On iOS, most dynamic analysis tools are based on @MASTG-TOOL-0139, a framework for developing runtime patches, or Frida, a dynamic introspection tool. For basic API monitoring, you can get away with not knowing all the details of how ElleKit or Frida work - you can simply use existing API monitoring tools.

On iOS, collecting basic information about a running process or an application can be slightly more challenging than compared to Android. On Android (or any Linux-based OS), process information is exposed as readable text files via _procfs_. Thus, any information about a target process can be obtained on a rooted device by parsing these text files. In contrast, on iOS there is no procfs equivalent present. Also, on iOS many standard UNIX command line tools for exploring process information, for instance lsof and vmmap, are removed to reduce the firmware size.

In this section, we will learn how to collect process information on iOS using command line tools like lsof. Since many of these tools are not present on iOS by default, we need to install them via alternative methods. For instance, lsof can be installed using @MASTG-TOOL-0047 (the executable is not the latest version available, but nevertheless addresses our purpose).
