---
title: Check App Notifications
profiles:

static_keywords:
  - notification

apis:
  - NotificationManager
  - NotificationCompat.Builder:https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder
    - setContentTitle
    - setContentText

---

## Overview

It is important to understand that [notifications](https://developer.android.com/guide/topics/ui/notifiers/notifications "Notifications Overview") should never be considered private. When a notification is handled by the Android system it is broadcasted system-wide and any application running with a [NotificationListenerService](https://developer.android.com/reference/kotlin/android/service/notification/NotificationListenerService "NotificationListenerService") can listen for these notifications to receive them in full and may handle them however it wants.

There are many known malware samples such as [Joker](https://research.checkpoint.com/2020/new-joker-variant-hits-google-play-with-an-old-trick/ "Joker Malware"), and [Alien](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise.html "Alien Malware") which abuses the `NotificationListenerService` to listen for notifications on the device and then send them to attacker-controlled C2 infrastructure. Commonly this is done in order to listen for two-factor authentication (2FA) codes that appear as notifications on the device which are then sent to the attacker.

Furthermore there are a number of apps on the Google Play Store that provide notification logging, which basically logs locally any notifications on the Android system. This highlights that notifications are in no way private on Android and accessible by any other app on the device.

For this reason all notification usage should be inspected for confidential or high risk information that could be used by malicious applications.

## Steps

### Static Analysis

1. [Disassemble](../../techniques.md#disassemble) or [decompile](../../techniques.md#decompile) the app
2. [string search](../../techniques.md#string-search) for [related APIs](#apis)
3. [Reverse](../../techniques.md#manual-reversed-code-review) the affected code and try to understand how the application is [generating the notifications](https://developer.android.com/training/notify-user/build-notification#SimpleNotification "Create a Notification") and which data ends up being shown.

### Dynamic Analysis

1. [install the app](../../techniques.md#install-an-app)
2. do [method tracing](../../techniques.md#method-tracing) on [related APIs](#apis)
3. Use all the mobile app functions at least once
4. Inspect the [method trace](../../../resources.md#method-trace) and evaluate if it contains any sensitive information.

## Evaluation

## Mitigation

### User Education

A safer alternative for the user would be to use a 2FA application that does not generate notifications.

### Encrypt Notifications

TBD