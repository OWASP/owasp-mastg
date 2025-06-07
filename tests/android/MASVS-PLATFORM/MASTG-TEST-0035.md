---
masvs_v1_id:
- MSTG-PLATFORM-9
masvs_v2_id:
- MASVS-PLATFORM-3
platform: android
title: Testing for Overlay Attacks
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

To test for [overlay attacks](../../../Document/0x05h-Testing-Platform-Interaction.md#overlay-attacks "Overlay Attacks") you need to check the app for usage of certain APIs and attributed typically used to protect against overlay attacks as well as check the Android version that app is targeting.

To mitigate these attacks please carefully read the general guidelines about Android View security in the [Android Developer Documentation](https://developer.android.com/reference/android/view/View#security "View Security"). For instance, the so-called _touch filtering_ is a common defense against tapjacking, which contributes to safeguarding users against these vulnerabilities, usually in combination with other techniques and considerations as we introduce in this section.

## Static Analysis

To start your static analysis you can check the app for the following methods and attributes (non-exhaustive list):

- Override [`onFilterTouchEventForSecurity`](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity%28android.view.MotionEvent%29 "onFilterTouchEventForSecurity") for more fine-grained control and to implement a custom security policy for views.
- Set the layout attribute [`android:filterTouchesWhenObscured`](https://developer.android.com/reference/android/view/View#attr_android:filterTouchesWhenObscured "android:filterTouchesWhenObscured") to true or call [`setFilterTouchesWhenObscured`](https://developer.android.com/reference/android/view/View.html#setFilterTouchesWhenObscured%28boolean%29 "setFilterTouchesWhenObscured").
- Check [FLAG_WINDOW_IS_OBSCURED](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_OBSCURED "FLAG_WINDOW_IS_OBSCURED") (since API level 9) or [FLAG_WINDOW_IS_PARTIALLY_OBSCURED](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_PARTIALLY_OBSCURED "FLAG_WINDOW_IS_PARTIALLY_OBSCURED") (starting on API level 29).

Some attributes might affect the app as a whole, while others can be applied to specific components. The latter would be the case when, for example, there is a business need to specifically allow overlays while wanting to protect sensitive input UI elements. The developers might also take additional precautions to confirm the user's actual intent which might be legitimate and tell it apart from a potential attack.

As a final note, always remember to properly check the API level that app is targeting and the implications that this has. For instance, [Android 8.0 (API level 26) introduced changes](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert windows") to apps requiring `SYSTEM_ALERT_WINDOW` ("draw on top"). From this API level on, apps using `TYPE_APPLICATION_OVERLAY` will be always [shown above other windows](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert Windows") having other types such as `TYPE_SYSTEM_OVERLAY` or `TYPE_SYSTEM_ALERT`. You can use this information to ensure that no overlay attacks may occur at least for this app in this concrete Android version.

## Dynamic Analysis

Abusing this kind of vulnerability on a dynamic manner can be pretty challenging and very specialized as it closely depends on the target Android version. For instance, for versions up to Android 7.0 (API level 24) you can use the following APKs as a proof of concept to identify the existence of the vulnerabilities.

- [Tapjacking POC](https://github.com/FSecureLABS/tapjacking-poc "Tapjacking POC"): This APK creates a simple overlay which sits on top of the testing application.
- [Invisible Keyboard](https://github.com/DEVizzi/Invisible-Keyboard "Invisible Keyboard"): This APK creates multiple overlays on the keyboard to capture keystrokes. This is one of the exploit demonstrated in Cloak and Dagger attacks.
