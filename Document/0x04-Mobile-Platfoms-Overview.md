# Mobile Platforms Overview

This section briefly describes the security mechanisms and underlying guarantees of Android and iOS.

## Android (Work in Progress)

Android is an open source platform that can be found nowadays on many devices:

* Mobile Phones and Tablets
* Wearables
* "Smart" devices in general like TVs

It also offers an application environment that supports not only pre-installed applications on the device, but also 3rd party applications that can be downloaded from marketplaces like Google Play. 

The software stack of Android comprises of different layers, where each layer is defining certain behaviour and offering specific services to the layer above. 

![Android Software Stack](https://source.android.com/security/images/android_software_stack.png)

On the lowest level Android is using the Linux Kernel where the core operating system is built up on. The hardware abstraction layer defines a standard interface for hardware vendors. HAL implementations are packaged into shared library modules (.so files). These modules will be loaded by the Android system at the appropriate time. The Android Runtime consists of the core libraries and the Dalvik VM (Virtual Machine). Applications are most often implemented in Java and compiled in Java class files and then compiled again into the dex format. The dex files are then executed within the Dalvik VM. With Android 4.4 the successor of Dalvik VM was introduced, called Android Runtime (ART). Applications are executed in the Android Application Sandbox that enforces isolation of application data and code execution from other applications on the device, that adds an additional layer of security. 

The Android Framework is creating an abstraction layer for all the layers below, so developers can implement Android Apps and can utilize the capabilites of Android without deeper knowledge of the layers below. It also offers a robust implementation that offers common security functions like secure IPC or cryptography. 


References: 
+ [Android Security](https://source.android.com/security/)
+ [HAL](https://source.android.com/devices/)
+ "Android Security: Attacks and Defenses" By Anmol Misra, Abhishek Dubey


## iOS (Work in progress)

As every platform, also iOS provides a SDK (Software Development Kit) that helps developers to develop, install, run and test native iOS Apps by offering different tools and interfaces. iOS applications are implemented either by using Objective-C or Swift. 

Objective-C is an object-oriented programming language that is based on C and is used on macOS and iOS to develop (mobile) applications. Even macOS and iOS itself is mainly implemented by using Objective-C. 

Swift is the successor of Objective-C and allows interoperability with the same and was introduced with Xcode 6 in 2014. 



![iOS Security Architecture (iOS Security Guide)](http://bb-conservation.de/sven/iOS_Security_Architecture.png)
*iOS Security Architecture (iOS Security Guide)*

References:
+ [iOS Technology Overview](https://developer.apple.com/library/content/documentation/Miscellaneous/Conceptual/iPhoneOSTechOverview/Introduction/Introduction.html#//apple_ref/doc/uid/TP40007898-CH1-SW1)
+ [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
+ [How iOS Security Really Works](https://developer.apple.com/videos/play/wwdc2016/705/)


## Mobile Applications Overview 

Mobile development has taken world to a ride and we have many different ways of developing applications for all mobile platforms.

* Native Apps:
   * **Android**: Applications are primarily written in Java by using the Android SDK. However code logic could be abstracted out as a C binary by using the Android NDK to provide low-level functionality and speed.
   * **iOS**: Primarily written in Objective C by using Xcode IDE. With introduction of Swift slowly the primary language is shifting to Swift.
* HTML5 Apps: The base for HTML5 Apps are JavaScript, CSS and HTML5 technologies. They are web sites but display effectively on mobile devices. 
* Hybrid Apps: Hybrid applications are basically web applications that are rendered in the native browser of the mobile operating system, for example UIWebView in iOS or WebView in Android. The base for Hybrid-Apps are JavaScript, CSS and HTML that are packaged in a native application. 

There are various frameworks which allow you to write software in one language and compile the application for multiple platforms. Examples for such frameworks are:
* [Phonegap](http://phonegap.com/)
* [Cordova](https://cordova.apache.org/)
* [Kony](http://www.kony.com/) 
* [B4X](https://www.b4x.com/)
