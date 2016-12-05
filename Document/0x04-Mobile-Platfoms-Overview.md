# Mobile Platforms Overview

This section briefly describes the security mechanisms and underlying guarantees of Android and iOS and also briefly touches on vulnerabilities of both OS itself.

## Android 

Android can be thought of as a software stack comprising different layers. Each layer manifesting well-defined behavior and providing specific services to the layer above it. Android uses the Linux kernel, which is at the bottom of the stack. Above the Linux kernel are native libraries and Android runtime (the Dalvik Virtual Machine [VM] and Core Libraries). Built on top of this is the Application framework, which enables Android to interact with the native libraries and kernel. The topmost layer comprises the Android applications.

![Android Software Stack](https://source.android.com/security/images/android_software_stack.png)

To help pentesters and developers to get a basic understanding of the Android architectures these layers are briefly described:

* **Applications**: By default, Android comes with a rich set of applications, including the browser, calendar, e-mail client and so forth. These applications are written in the Java programming language. Google Play (the main marketplace for Android) provides alternatives to these applications and many other applications with different functions. 
* **Android Framework**: The Android application framework provides a rich set of classes provided (for developers) through Java APIs for applications. This is done through various Application Manager services. The most important components within this layer are Activity Manager, Resource Manager, Location Manager, and Notification Manager.
* **Native Libraries**: Android includes a set of C and C++ libraries used by different components of the Android system. Developers use these libraries through the Android application framework. At times, this layer is referred to as the “native layer” as the code here is written in C and C++ and optimized for the hardware, as opposed to the Android applications and framework, which are written in Java. Android applications can access native capabilities through Java Native Interface (JNI) calls.
* **Android Runtime**: The Android Runtime can be thought of as comprising two different components: the Dalvik VM and Core Libraries. These applications are then compiled into Java class files. However, Android does not run these class files as they are. Java class files are re-compiled into dex format, which adds one more step to the process before the applications can be executed on the Android platform. The Dex format is then executed in a custom Java Virtual Machine (JVM)-like implementation—the Dalvik VM. On newer Android versions (starting with Android 4.4) the Dalvik VM is replaced by the Android Runtime (ART). ART and Dalvik are compatible runtimes, both running dex bytecode. From an analyst's perspective the runtime is not important, even though there are some key differences for executing apps (e.g. Ahead-of-time compilation on ART vs. Just-in-time compilation on Dalvik, and improved garbage collection on ART)
* **HAL (Hardware Abstraction Layer)**: The hardware abstraction layer defines a standard interface for hardware vendors. HAL implementations are packaged into shared library modules (.so files). These modules will be loaded by the Android system at the appropriate time.

![Hardware Abstraction Layer components](https://source.android.com/devices/images/ape_fwk_hal.png)

* **Linux Kernel**: The Linux kernel is the bottom of the Android stack. It is not the traditional Linux system that is usually seen (e.g., Ubuntu). Rather, Android has taken the Linux kernel code and modified it to run in an embedded environment. Thus, it does not have all the features of a traditional Linux distribution. Specifically, there is no X window system in the Android Linux kernel. Nor are there all the GNU utilities generally found in /bin in a traditional Linux environment (e.g., sed, etc.).

References: 

[1] Android Security - https://source.android.com/security/

[2] HAL - https://source.android.com/devices/



## iOS




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
