
## Mobile App Taxonomy

The following section is a brief introduction to the 3 different types of mobile applications, namely (1) Native Apps, (2) Hybrid Apps and (3) Web Apps. Before we dive into them, it is essential to first understand what a mobile app is.

### Mobile App

The term `mobile app` refers to applications (self-contained computer programs), designed to execute and enhance the functionality of a mobile device. In this guide we will focus on the mobile apps designed to run on Android and iOS operating systems, as cumulatively they take more than 99% of the market share<sup>[12]</sup>. Due to the expansion of these operating systems to other device types, like smart watches, TVs, cars, the more general term `app` is more appropriate. Nevertheless, for historic reasons, both terms are used interchangeably to refer to an application that can run on some of these systems, regardless of the exact device type.

Today, mobile internet usage has surpassed desktop usage for the first time in history and mobile apps are the most widespread kind of applications<sup>[10]</sup>, making mobile devices increasingly likely targets for malicious actors.

### Native App

Most operating systems, including Android and iOS, come with a set of high-level APIs that can be used to develop applications specifically for that system. Such applications are called `native` for the system for which they have been developed. Usually, when discussing a `mobile app`, the assumption is that it is a `native app`, implemented in the standard programming languages for that operating system - either Objective-C or Swift for iOS, and Java or Kotlin for Android.

Native mobile apps can provide fast performance and a high degree of reliability. They usually adhere to platform-specific design principles (e.g. the Android Design Principles<sup>[13]</sup>), and provide a more consistent UI than `hybrid` and `web` apps. Due to their close integration with the operating system, native apps have access to almost every component of the device (camera, sensors, hardware backed key stores, etc.)

There can be some ambiguity when discussing `native` apps for Android. Android provides two sets of APIs to develop against - the Android SDK and the Android NDK. The SDK (or Software Development Kit) is a Java API and is the default API against which applications are built. The NDK (or Native Development Kit) is a C/C++ based API used for developing application components that require specific optimization, or which can otherwise benefit from access to lower level APIs (such as OpenGL). Normally, you can only distribute apps built with the SDK, which potentially can also consum NDK APIs. Therefore we say that Android `native **apps**` (built with the SDK) can have `native **code**` (built with the NDK).

The most obvious downside of native apps is that they target only one specific platform. To build the same app for both Android and iOS, one needs to maintain two independent code bases, or introduce often complex development tools to port a single code base to two platforms (e.g. Xamarin)

<!-- Note that Xamarin, unlike Cordova, actually creates native binaries for iOS and Android apps -->

### Web App

Mobile Web apps, or simply Web apps, are websites designed to look and feel like a native app. They run in a browser and are usually developed in HTML5. Launcher icons may be created to give starting-up the app a native feel, but these often simply act as browser bookmarks, opening the default web browser and loading the bookmarked webpage.

Web apps have limited integration with the general components of the device (usually being sandboxed in the browser), and may have noticeable differences in performance from native apps. Since they typically target multiple platforms, their UIs do not follow some of the design principles users of a specific platform are used to. Their biggest advantage is reduced development and maintenance costs arising from having a single codebase, as well as allowing developers to distribute updates without engaging the platform specific app stores (such as by simply changing HTML files on the webserver hosting the application).

### Hybrid App

Hybrid apps attempt to fill the gap between native and web apps. Namely, hybrid apps are (distributed and executed as) native apps, that have majority of their content implemented on top of web technologies, running in an embedded web browser (web view). As such, hybrid apps inherit some of the pros and cons of both native and web apps.

A web-to-native abstraction layer enables access to device capabilities for hybrid apps that are not accessible to mobile web applications. Depending on the framework used for developing, one code base can result in multiple applications, targeting separate platforms, with a UI closely resembling that of the targeted platform. Nevertheless, usually significant effort is required to exactly match the look and feel of a native app.

Following is a non-exhaustive list of more popular frameworks for developing Hybrid Apps:

* Apache Cordova - https://cordova.apache.org/
* Framework 7 - http://framework7.io/
* Ionic - https://ionicframework.com/
* jQuery Mobile - https://jquerymobile.com/
* Native Script - https://www.nativescript.org/
* Onsen UI - https://onsen.io/
* React Native - http://www.reactnative.com/
* Sencha Touch - https://www.sencha.com/products/touch/
