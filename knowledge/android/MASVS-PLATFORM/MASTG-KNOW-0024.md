---
masvs_category: MASVS-PLATFORM
platform: android
title: Pending Intents
---

Often while dealing with complex flows during app development, there are situations where an app A wants another app B to perform a certain action in the future, on app A's behalf. Trying to implement this by only using `Intent`s leads to various security problems, like having multiple exported components. To handle this use case in a secure manner, Android provides the [`PendingIntent`](https://developer.android.com/reference/android/app/PendingIntent "PendingIntent") API.

`PendingIntent` are most commonly used for [notifications](https://developer.android.com/develop/ui/views/notifications "Android Notifications"), [app widgets](https://developer.android.com/develop/ui/views/appwidgets/advanced#user-interaction "app widgets"), [media browser services](https://developer.android.com/guide/topics/media-apps/audio-app/building-a-mediabrowserservice "media browser services"), etc. When used for notifications, `PendingIntent` is used to declare an intent to be executed when a user performs an action with an application's notification. The notification requires a callback to the application to trigger an action when the user clicks on it.

Internally, a `PendingIntent` object wraps a normal `Intent` object (referred as base intent) that will eventually be used to invoke an action. For example, the base intent specifies that an activity A should be started in an application. The receiving application of the `PendingIntent`, will unwrap and retrieve this base intent and invoke the activity A by calling the `PendingIntent.send` function.

A typical implementation for using `PendingIntent` is below:

```java
Intent intent = new Intent(applicationContext, SomeActivity.class);     // base intent

// create a pending intent
PendingIntent pendingIntent = PendingIntent.getActivity(applicationContext, 0, intent, PendingIntent.FLAG_IMMUTABLE);

// send the pending intent to another app
Intent anotherIntent = new Intent();
anotherIntent.setClassName("other.app", "other.app.MainActivity");
anotherIntent.putExtra("pendingIntent", pendingIntent);
startActivity(anotherIntent);
```

What makes a `PendingIntent` secure is that, unlike a normal `Intent`, it grants permission to a foreign application to use the `Intent` (the base intent) it contains, as if it were being executed by your application's own process. This allows an application to freely use them to create callbacks without the need to create exported activities.

If not implemented correctly, a malicious application can **hijack** a `PendingIntent`. For example, in the notification example above, a malicious application with `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` can bind to the notification listener service and retrieve the pending intent.

There are certain security pitfalls when implementing `PendingIntent`s, which are listed below:

- **Mutable fields**: A `PendingIntent` can have mutable and empty fields that can be filled by a malicious application. This can lead to a malicious application gaining access to non-exported application components. Using the [`PendingIntent.FLAG_IMMUTABLE` flag](https://developer.android.com/reference/android/app/PendingIntent#FLAG_IMMUTABLE "FLAG_IMMUTABLE") makes the `PendingIntent` immutable and prevents any changes to the fields. Prior to Android 12 (API level 31), the `PendingIntent` was mutable by default, while since Android 12 (API level 31) it is changed to [immutable by default](https://developer.android.com/reference/android/app/PendingIntent#FLAG_MUTABLE "immutable by default") to prevent accidental vulnerabilities.

- **Use of implicit intent**: A malicious application can receive a `PendingIntent` and then update the base intent to target the component and package within the malicious application. As a mitigation, ensure that you explicitly specify the exact package, action and component that will receive the base intent.

The most common case of `PendingIntent` attack is when a malicious application is able to intercept it.

For further details, check the Android documentation on [using a pending intent](https://developer.android.com/guide/components/intents-filters#PendingIntent "using a pending intent").
