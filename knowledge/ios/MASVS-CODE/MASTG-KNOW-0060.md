---
masvs_category: MASVS-CODE
platform: ios
title: Memory Corruption Bugs
---

iOS applications have various ways to run into [memory corruption bugs](0x04h-Testing-Code-Quality.md#memory-corruption-bugs): first there are the native code issues which have been mentioned in the general Memory Corruption Bugs section. Next, there are various unsafe operations with both Objective-C and Swift to actually wrap around native code which can create issues. Last, both Swift and Objective-C implementations can result in memory leaks due to retaining objects which are no longer in use.

Learn more:

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>
