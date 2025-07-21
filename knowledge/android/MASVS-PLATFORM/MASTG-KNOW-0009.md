---
masvs_category: MASVS-PLATFORM
platform: android
title: Implicit Intents
---

An Intent is a messaging object that you can use to request an action from another application component. Although intents facilitate communication between components in a variety of ways, there are three basic use cases: starting an activity, starting a service, and delivering a broadcast.

According to the [Android Developers Documentation](https://developer.android.com/guide/components/intents-filters#Types), Android provides two types of intents:

- **Explicit intents** specify which application will satisfy the intent by providing either the target app's package name or a fully qualified component class name. Typically, you'll use an explicit intent to start a component in your own app, because you know the class name of the activity or service you want to start. For example, you might want to start a new activity in your app in response to a user action, or start a service to download a file in the background.

  ```java
  // Note the specification of a concrete component (DownloadActivity) that is started by the intent.
  Intent downloadIntent = new Intent(this, DownloadActivity.class);
  downloadIntent.setAction("android.intent.action.GET_CONTENT")
  startActivityForResult(downloadIntent);
  ```

- **Implicit intents** do not name a specific component, but instead declare a general action to be performed that another app's component can handle. For example, if you want to show the user a location on a map, you can use an implicit intent to ask another capable app to show a specific location on a map. Another example is when the user clicks on an email address within an app, where the calling app does not want to specify a specific email app and leaves that choice up to the user.

  ```java
  // Developers can also start an activity by just setting an action that is matched by the intended app.
  Intent downloadIntent = new Intent();
  downloadIntent.setAction("android.intent.action.GET_CONTENT")
  startActivityForResult(downloadIntent);
  ```

The use of implicit intents can lead to multiple security risks, e.g. if the calling app processes the return value of the implicit intent without proper verification or if the intent contains sensitive data, it can be accidentally leaked to unauthorized third-parties.

You can refer to this [blog post](https://blog.oversecured.com/Interception-of-Android-implicit-intents/ "Interception of Android implicit intents"), [this article](https://wiki.sei.cmu.edu/confluence/display/android/DRD03-J.+Do+not+broadcast+sensitive+information+using+an+implicit+intent "DRD03-J. Do not broadcast sensitive information using an implicit intent") and [CWE-927](https://cwe.mitre.org/data/definitions/927.html "CWE-927: Use of Implicit Intent for Sensitive Communication") for more information about the mentioned problem, concrete attack scenarios and recommendations.
