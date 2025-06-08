---
masvs_v1_id:
- MSTG-CODE-8
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: Memory Corruption Bugs
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

Are there native code parts? If so: check for the given issues in the general memory corruption section. Native code is a little harder to spot when compiled. If you have the sources then you can see that C files use .c source files and .h header files and C++ uses .cpp files and .h files. This is a little different from the .swift and the .m source files for Swift and Objective-C. These files can be part of the sources, or part of third party libraries, registered as frameworks and imported through various tools, such as Carthage, the Swift Package Manager or Cocoapods.

For any managed code (Objective-C / Swift) in the project, check the following items:

- The doubleFree issue: when `free` is called twice for a given region instead of once.
- Retaining cycles: look for cyclic dependencies by means of strong references of components to one another which keep materials in memory.
- Using instances of `UnsafePointer` can be managed wrongly, which will allow for various memory corruption issues.
- Trying to manage the reference count to an object by `Unmanaged` manually, leading to wrong counter numbers and a too late/too soon release.

[A great talk is given on this subject at Realm academy](https://academy.realm.io/posts/russ-bishop-unsafe-swift/ "Russh Bishop on Unsafe Swift") and [a nice tutorial to see what is actually happening](https://www.raywenderlich.com/780-unsafe-swift-using-pointers-and-interacting-with-c "Unsafe Swift: Using Pointers And Interacting With C") is provided by Ray Wenderlich on this subject.

> Please note that with Swift 5 you can only deallocate full blocks, which means the playground has changed a bit.

## Dynamic Analysis

There are various tools provided which help to identify memory bugs within Xcode, such as the Debug Memory graph introduced in Xcode 8 and the Allocations and Leaks instrument in Xcode.

Next, you can check whether memory is freed too fast or too slow by enabling `NSAutoreleaseFreedObjectCheckEnabled`, `NSZombieEnabled`, `NSDebugEnabled` in Xcode while testing the application.

There are various well written explanations which can help with taking care of memory management. These can be found in the reference list of this chapter.
