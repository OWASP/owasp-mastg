---
masvs_category: MASVS-CODE
platform: android
title: Third-Party Libraries
---

Android apps often make use of third party libraries. These third party libraries accelerate development as the developer has to write less code in order to solve a problem. There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `Mockito` used for testing and libraries like `JavaAssist` used to compile certain other libraries.
- Libraries that are packed within the actual production application, such as `Okhttp3`.

These libraries can lead to unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example are the versions of `OKHTTP` prior to 2.7.5 in which TLS chain pollution was possible to bypass SSL pinning.
- A library can no longer be maintained or hardly be used, which is why no vulnerabilities are reported and/or fixed. This can lead to having bad and/or vulnerable code in your application through the library.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its sourcecode. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.
