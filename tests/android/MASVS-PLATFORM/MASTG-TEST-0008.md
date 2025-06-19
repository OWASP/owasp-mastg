---
masvs_v1_id:
- MSTG-STORAGE-7
masvs_v2_id:
- MASVS-PLATFORM-3
platform: android
title: Checking for Sensitive Data Disclosure Through the User Interface
masvs_v1_levels:
- L1
- L2
profiles: [L2]
---

## Overview

## Static Analysis

Carefully review all UI components that either show such information or take it as input. Search for any traces of sensitive information and evaluate if it should be masked or completely removed.

### Text Fields

To make sure an application is masking sensitive user input, check for the following attribute in the definition of `EditText`:

```xml
android:inputType="textPassword"
```

With this setting, dots (instead of the input characters) will be displayed in the text field, preventing the app from leaking passwords or pins to the user interface.

### App Notifications

When statically assessing an application, it is recommended to search for any usage of the `NotificationManager` class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is [generating the notifications](https://developer.android.com/training/notify-user/build-notification#SimpleNotification "Create a Notification").

These code locations can be fed into the Dynamic Analysis section below, providing an idea of where in the application notifications may be dynamically generated.

## Dynamic Analysis

To determine whether the application leaks any sensitive information to the user interface, run the application and identify components that could be disclosing information.

### Text Fields

If the information is masked by, for example, replacing input with asterisks or dots, the app isn't leaking data to the user interface.

### App Notifications

To identify the usage of notifications run through the entire application and all its available functions looking for ways to trigger any notifications. Consider that you may need to perform actions outside of the application in order to trigger certain notifications.

While running the application you may want to start tracing all calls to functions related to the notifications creation, e.g. `setContentTitle` or `setContentText` from [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder). Observe the trace in the end and evaluate if it contains any sensitive information.
