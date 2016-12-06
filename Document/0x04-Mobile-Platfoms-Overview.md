# Mobile Platforms Overview

This section briefly describes the security mechanisms and underlying guarantees of Android and iOS.

## Android 

Android is an open source platform that can be found nowadays on many devices:

* Mobile Phones and Tablets
* Wearables
* "Smart" devices in general like TVs

It also offers an application environment that supports not only applications shipped with the device, but also is able to download 3rd party applications from marketplaces like Google Play. 

The software stack of Android comprises of different layers, where each layer is defining certain behaviour and offering specific services to the layer above. 

![Android Software Stack](https://source.android.com/security/images/android_software_stack.png)

On the lowest level Android is using the Linux Kernel where the core operating system is built up on. The hardware abstraction layer defines a standard interface for hardware vendors. HAL implementations are packaged into shared library modules (.so files). These modules will be loaded by the Android system at the appropriate time. The Android Runtime consists of the core libraries and the Dalvik VM (Virtual Machine). Applications are most often implemented in Java and compiled in Java class files and then compiled again into the dex format. The dex files are then executed within the Dalvik VM. With Android 4.4 the successor of Dalvik VM was introduced, called Android Runtime (ART).

The Android Framework is creating an abstraction layer for all the layers below, so developers can implement Android Apps and can utilize the capabilites of Android without deeper knowledge of the layers below.  



References: 
+ [Android Security](https://source.android.com/security/)
+ [HAL](https://source.android.com/devices/)
+ "Android Security: Attacks and Defenses" By Anmol Misra, Abhishek Dubey


## iOS (Work in progress)

As every platform, also iOS provides a SDK (Software Development Kit) that helps developers to develop, install, run and test native iOS Apps by offering different tools and interfaces. iOS applications are implemented either by using Objective-C or Swift. 

Objective-C is an object-oriented programming language that is based on C and is used on macOS and iOS to develop (mobile) applications. Even macOS and iOS itself is mainly implemented by using Objective-C. 

Swift is the successor of Objective-C and allows interoperability with the same and was introduced with Xcode 6 in 2014. 



References:
+ [iOS Technology Overview](https://developer.apple.com/library/content/documentation/Miscellaneous/Conceptual/iPhoneOSTechOverview/Introduction/Introduction.html#//apple_ref/doc/uid/TP40007898-CH1-SW1)

![iOS Security Architecture (iOS Security Guide)](http://bb-conservation.de/sven/iOS_Security_Architecture.png)
*iOS Security Architecture (iOS Security Guide)*


References: 
+ [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
+ [How iOS Security Really Works](https://developer.apple.com/videos/play/wwdc2016/705/)

## Mobile Applications Overview (Work in progress)

Mobile development has taken world to a ride and we have many different ways of developing applications for all mobile platforms.

* Android: Applications are primarily written in Java. However code logic could be abstracted out as a C binary to provide low-level functionality and speed.
* iOS: Primarily written in Objective C. With introduction of Swift slowly the primary language is shifting to Swift
* Hybrid: TBD
* HTML5-Apps: TBD

Besides these there are various frameworks like Phonegap or Kony which allow you to write software in one language and compile the application for multiple platforms.
Examples for such frameworks are:
* Phonegap
* Kony 
* B4X
