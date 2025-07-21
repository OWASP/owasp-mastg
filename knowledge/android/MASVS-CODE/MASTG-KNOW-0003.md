---
masvs_category: MASVS-CODE
platform: android
title: Memory Corruption Bugs
---

Android applications run on a VM where most of the memory corruption issues have been taken care off. This does not mean that there are no memory corruption bugs. Take [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") for instance, which is related to serialization issues using Parcels. Next, in native code, we still see the same issues as we explained in the general memory corruption section. Last, we see memory bugs in supporting services, such as with the Stagefright attack as shown [at BlackHat](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright").

Memory leaks are often an issue as well. This can happen for instance when a reference to the `Context` object is passed around to non-`Activity` classes, or when you pass references to `Activity` classes to your helper classes.
