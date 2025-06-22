# Mobile Application Taxonomy

When we use the term "mobile application" or "mobile app," we are referring to a self-contained computer program designed to execute on a mobile device. At the time of publication, the Android and iOS operating systems cumulatively comprise [more than 99% of the mobile OS market share](https://www.idc.com/promo/smartphone-market-share/os) and mobile Internet usage has far surpassed desktop Internet usage. This means that mobile apps are the [most widespread types of Internet-capable apps](https://www.idc.com/promo/smartphone-market-share/os).

Also, this guide uses the term "app" as a general term which refers to any kind of application that runs on a mobile OS. Usually, apps run directly on the platform for which they're designed, run on top of a smart device's mobile browser, or they use a mix of these two methods.

In this chapter, will discuss the following types of apps:

- [Native Apps](#native-apps)
- [Cross-platform Mobile Frameworks](#cross-platform-mobile-frameworks)
- [Web Apps](#web-apps)
- [Hybrid Apps](#hybrid-apps)
- [Progressive Web Apps](#progressive-web-apps)

## Native Apps

If a mobile app is developed with a Software Development Kit (SDK) for developing apps specific to a mobile OS, they are referred to as _native_ to their OS. If we are discussing a native app, we presume it was implemented in a standard programming language for that mobile operating system - Objective-C or Swift for iOS, and Java or Kotlin for Android.

Because they are designed for a specific OS with the tools meant for that OS, _native apps_ have the capability to provide the fastest performance with the highest degree of reliability. They usually adhere to platform-specific design principles (e.g. the [Android Design Principles](https://developer.android.com/design "Android Design Principles")), which usually leads to a more consistent user interface (UI) compared to _hybrid_ or _web_ apps. Due to their close integration with the operating system, _native apps_ generally can directly access almost every component of the device (camera, sensors, hardware-backed key stores, etc.).

However, since Android provides two development kits - the Android SDK and the Android NDK, there is some ambiguity to the term _native apps_ for this platform. While the SDK (based on the Java and Kotlin programming language) is the default for developing apps, the platform's NDK (or Native Development Kit) is a C/C++ kit used for developing binary libraries that can directly access lower level APIs (such as OpenGL). These libraries can be included in regular apps built with the SDK. Therefore, we say that Android _native apps_ (i.e. built with the SDK) may have _native_ code built with the NDK.

## Cross-platform Mobile Frameworks

The most obvious disadvantage of _native apps_ is that they are limited to one specific platform. If developers want to build their app for both Android and iOS, one needs to maintain two independent code bases, or introduce often complex development tools to port a single code base to two platforms.

Here are some cross-platform mobile frameworks that allow developers to compile a single codebase for different targets, including both Android and iOS:

- [Xamarin](https://dotnet.microsoft.com/apps/xamarin "Xamarin")
- [MAUI](https://dotnet.microsoft.com/en-us/apps/maui ".NET MAUI")
- [Flutter](https://flutter.dev/ "Google Flutter")
- [React Native](https://reactnative.dev/ "React Native")
- [Unity](https://unity.com/ "Unity")

If an app is developed using these frameworks, the app will use the internal APIs native to each system and offer performance equivalent to native apps. Also, these apps can make use of all device capabilities, including the GPS, accelerometer, camera, the notification system, etc. Even though an app created using one of these frameworks is functionally equivalent to a true native app, they are typically not referred to as such. The term _native app_ is used for apps created with the OS's native SDK, while apps created using one of these frameworks are typically called cross-platform apps.

It's important to know when an app uses a cross-platform mobile framework, because they typically require specific tools to perform static or dynamic analysis. The actual application logic is typically located in framework-specific files inside the app, even though the app also contains the typical code that you would see in a _native app_. This native code is however usually only used to initialize the cross-platform framework, and provide bindings between the native system API and the framework SDK through so called platform-specific bindings.

Although it is rare, apps can combine native code and cross-platform frameworks, or even multiple cross-platform frameworks, so it's important to identify all the used technologies to correctly cover the entire attack surface of the app.

## Web Apps

Mobile web apps (or simply, _web apps_) are websites designed to look and feel like a _native app_. These apps run in the device's browser and are usually developed in HTML5, much like a modern web page. Launcher icons may be used to parallel the same feel of accessing a _native app_; however, these icons are essentially the same as a browser bookmark, simply opening the default web browser to load the referenced web page.

Because they run within the confines of a browser, web apps have limited integration with the general components of the device (i.e. they are "sandboxed") and their performance is usually inferior compared to native apps. Since developers usually target multiple platforms with a web app, their UIs generally do not follow the design principles of any specific platform. However, _web apps_ are popular because developers can use a single code base to reduce development and maintenance costs and distribute updates without going through the platform-specific app stores. For example, a change to the HTML file for a _web app_ can serve as viable, cross-platform update whereas an update to a store-based app requires considerably more effort.

## Hybrid Apps

_Hybrid apps_ are a specific type of _cross-platform app_ which try to benefit from the best aspects of _native_ and _web apps_. This type of app executes like a _native app_, but a majority of the processes rely on web technologies, meaning a portion of the app runs in an embedded web browser (commonly called "WebView"). As such, _hybrid apps_ inherit both pros and cons of _native_ and _web apps_. These apps can use a web-to-native abstraction layer to access to device capabilities that are not accessible to a pure _web app_. Depending on the framework used for development, a _hybrid app_ code base can generate multiple apps that target different platforms and take advantage of UI elements that closely resemble a device's original platform.

Here are some popular frameworks for developing _hybrid apps_:

- [Apache Cordova](https://cordova.apache.org/ "Apache Cordova")
- [Framework 7](https://framework7.io/ "Framework 7")
- [Ionic](https://ionicframework.com/ "Ionic")
- [Native Script](https://www.nativescript.org/ "Native Script")
- [Onsen UI](https://onsen.io/ "Onsen UI")
- [Sencha Ext JS](https://www.sencha.com/products/extjs/ "Sencha Ext JS")

## Progressive Web Apps

_Progressive web apps_ (PWAs) combine different open standards of the web offered by modern browsers to provide benefits of a rich mobile experience. A Web App Manifest, which is a simple JSON file, can be used to configure the behavior of the app after "installation". These apps load like regular web pages, but differ from usual web apps in several ways.

For example, it's possible to work offline and access to mobile device hardware is possible, which has been a capacity that was only available to _native apps_. PWAs are supported by both Android and iOS, but not all hardware features are yet available. For example, Push Notifications, Face ID on iPhone X, or ARKit for augmented reality is not available yet on iOS.
