## Mobile App Taxonomy

The term "mobile app" refers to a self-contained computer program designed to execute on a mobile device. Today, the Android and iOS operating systems cumulatively comprise [more than 99% of the mobile OS market share](http://www.idc.com/promo/smartphone-market-share/os). Additionally, mobile Internet usage has surpassed desktop usage for the first time in history, making mobile browsing and apps the [most widespread kind of Internet-capable applications](http://www.idc.com/promo/smartphone-market-share/os), considering the market saturation of smart devices.

> In this guide, we'll use the term "app" as a general term for referring to any kind of application running on popular mobile OSes.

Throughout this guide, we will focus on apps for the two platforms dominating the market: Android and iOS. Mobile devices are currently the most common item classification running these platforms – increasingly, the platforms (in particularly, Android) run on other devices, such as smartwatches, TVs, car navigation/audio systems, and other embedded systems. 

In a basic sense, apps are designed to run either directly on the platform for which they’re designed, on top of a smart device’s mobile browser, or using a mix of the two. Throughout the following chapter, we will define characteristics that qualify an app for its respective place in mobile app taxonomy as well as discuss differences for each variation.

### Native App

Most operating systems, including Android and iOS, come with a set of high-level APIs used to develop applications specific to the OS. Such applications are referred to as *native* to the system for which they have been developed. When discussing an app, the general assumption is that it is of this design, further implemented in a standard programming language for the respective operating system - either Objective-C or Swift for iOS, and Java or Kotlin for Android.

Native apps inherently have the capability to provide the fastest performance with the highest degree of reliability. They usually adhere to platform-specific design principles (e.g. the [Android Design Principles](https://developer.android.com/design/get-started/principles.html "Android Design Principles")), which tends to provide a more consistent user interface (UI), compared to *hybrid* or *web* apps. Due to their close integration with the operating system, native apps can directly access almost every component of the device (camera, sensors, hardware-backed key stores, etc.)

With respect to the previous statement, some ambiguity exists when discussing *native apps* for Android as the platform provides two sets of APIs for development - the Android SDK and the Android NDK. The SDK (or Software Development Kit) is a Java API and the current default for developing apps. The NDK (or Native Development Kit) is a C/C++ API used for developing application components requiring specific optimization, benefiting from access to lower level APIs (such as OpenGL).

Normally with Android, you can only distribute apps built with the SDK which can incorporate some developmental features from NDK APIs. Therefore, we say that Android *native apps* (i.e. built with the SDK) may have *native* code also built with the NDK.

The most obvious downside of *native apps* is that they target only one specific platform. To build the same app for both Android and iOS, one needs to maintain two independent code bases, or introduce often complex development tools to port a single code base to two platforms (e.g. [Xamarin](https://www.xamarin.com/)).

<!-- Note that Xamarin, unlike Cordova, actually creates native binaries for iOS and Android apps -->

### Web App

Mobile web apps (or simply, *web apps*) are websites designed to look and feel like a *native app*. These apps run on top of a device’s browser and are usually developed in HTML5, much like a modern webpage. Launcher icons may be created to parallel the same feel of accessing a *native app*; however, these icons are essentially the same as a browser bookmark, simply opening the default web browser to load the referenced web page.

Web apps have limited integration with the general components of the device as they run within the confines of a browser (i.e. they are “sandboxed”) and usually lack in performance, compared to *native apps*. Since a *web app* typically targets multiple platforms, their UIs do not follow some of the design principles of a specific platform, as much of the functionality is determined by the browser. The biggest advantage is reduced development and maintenance costs associated with a single code base as well as enabling developers to distribute updates without engaging the platform-specific app stores. For example, a change to the HTML file for app can serve as viable, cross-platform update whereas an update to store-based app requires considerably more effort.

### Hybrid App

Hybrid apps attempt to fill the gap between *native* and *web apps*. A *hybrid app* executes like a *native app*, but a majority of the processes rely on web technologies, meaning a portion of the app runs in an embedded web browser (commonly called “web view”). As such, hybrid apps inherit both pros and cons of *native* and *web apps*.

A web-to-native abstraction layer enables access to device capabilities for *hybrid apps* not accessible to a pure *web app*. Depending on the framework used for development, one code base can result in multiple applications that targeting different platforms, with a UI closely resembling that of the original platform for which the app was developed. Despite the web component of a *hybrid app*, a significant amount of effort is usually required to match the aesthetics and functionality of the original app.

Following is a non-exhaustive list of more popular frameworks for developing *hybrid apps*:

- [Apache Cordova](https://cordova.apache.org/)
- [Framework 7](http://framework7.io/)
- [Ionic](https://ionicframework.com/)
- [jQuery Mobile](https://jquerymobile.com/)
- [Native Script](https://www.nativescript.org/)
- [Onsen UI]( https://onsen.io/)
- [React Native](http://www.reactnative.com/)
- [Sencha Touch](https://www.sencha.com/products/touch/)
