---
masvs_category: MASVS-PLATFORM
platform: android
title: App Permissions
---

Android assigns a distinct system identity (Linux user ID and group ID) to every installed app. Because each Android app operates in a process sandbox, apps must explicitly request access to resources and data that are outside their sandbox. They request this access by [declaring the permissions](https://developer.android.com/guide/topics/permissions/overview "Permissions on Android") they need to use system data and features. Depending on how sensitive or critical the data or feature is, the Android system will grant the permission automatically or ask the user to approve the request.

To enhance user privacy and mitigate privacy risks, it is crucial for Android apps to minimize permission requests and only request access to sensitive information when absolutely necessary. The Android developer documentation offers valuable insights and best practices to help apps achieve the same level of functionality without requiring direct access to sensitive resources:

- [Minimize your permission requests](https://developer.android.com/training/permissions/evaluating "Minimize your permission requests")
- [App permissions best practices](https://developer.android.com/training/permissions/usage-notes "App permissions best practices")
- [Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170 "Permissions and APIs that Access Sensitive Information")

Android permissions can be classified into distinct categories depending on the extent of restricted data access and permitted actions that they grant to an app. This classification includes the so-called ["Protection Level"](https://developer.android.com/guide/topics/manifest/permission-element#plevel "`<permission> - android:protectionLevel`") as shown on the [permissions API reference page](https://developer.android.com/reference/android/Manifest.permission "Manifest.permission") and [AndroidManifest.xml Source Definitions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/master/core/res/AndroidManifest.xml#819 "android.googlesource.com - AndroidManifest.xml").

- [**Install-time permissions**](https://developer.android.com/guide/topics/permissions/overview#install-time "Install-time permissions"): grant limited access to restricted data or let the app perform restricted actions that minimally affect the system or other apps. They are granted automatically at installation time (Android 6.0 (API level 23) or higher).
    - Protection Level: `normal`. Grants apps access to isolated application-level features with minimal risk to other apps, the user, and the system. Example: `android.permission.INTERNET`
    - Protection Level: `signature`. Granted only to apps signed with the same certificate as the one used to sign the declaring app. Example: `android.permission.ACCESS_MOCK_LOCATION`
    - Protection Level: `signatureOrSystem`. Reserved for system-embedded apps or those signed with the same certificate as the one used to sign the declaring app. Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`. Old synonym for `signature|privileged`. Deprecated in API level 23.
- [**Runtime permissions**](https://developer.android.com/training/permissions/requesting "Request runtime permissions"): require prompting the user at runtime for explicit approval.
    - Protection Level: `dangerous`. Grant additional access to restricted data or let the app perform restricted actions that more substantially affect the system and other apps.
- [**Special permissions**](https://developer.android.com/training/permissions/requesting-special "Request special permissions"): require the user to navigate to **Settings > Apps > Special app access** and give explicit consent.
    - Protection Level: `appop`. Grant access to system resources that are particularly sensitive such as displaying and drawing over other apps or accessing all storage data.
- [**Custom permissions**](https://developer.android.com/guide/topics/permissions/defining "Define a custom app permission") in order to share their own resources and capabilities with other apps.
    - Protection Level: `normal`, `signature` or `dangerous`.

Independently from the assigned Protection Level, it is important to consider the risk that a permission might be posing considering the additional guarded capabilities, this is especially important for preloaded apps. The following table presents a representative set of Android permissions categorized by associated risk as defined in this [paper](https://www.android-device-security.org/publications/2020-lau-uraniborg/Lau_2020_Uraniborg_Scoring_Whitepaper_20200827.pdf "Uraniborg's Device Preloaded App Risks Scoring Metrics") which leverages the set of (privileged) permissions and entrance points to an app to estimate its attack surface.

| Risk Category    | Permissions                                                     | Protection Level  |
|------------------|-----------------------------------------------------------------|-------------------|
| **ASTRONOMICAL** | `android.permission.INSTALL_PACKAGES`                           | signature         |
| **CRITICAL**     | `android.permission.COPY_PROTECTED_DATA`                        | signature         |
| **CRITICAL**     | `android.permission.WRITE_SECURE_SETTINGS`                      | signature         |
| **CRITICAL**     | `android.permission.READ_FRAME_BUFFER`                          | signature         |
| **CRITICAL**     | `android.permission.MANAGE_CA_CERTIFICATES`                     | signature         |
| **CRITICAL**     | `android.permission.MANAGE_APP_OPS_MODES`                       | signature         |
| **CRITICAL**     | `android.permission.GRANT_RUNTIME_PERMISSIONS`                  | signature         |
| **CRITICAL**     | `android.permission.DUMP`                                       | signature         |
| **CRITICAL**     | `android.permission.CAMERA`                                     | dangerous         |
| **CRITICAL**     | `android.permission.SYSTEM_CAMERA`                              | signatureOrSystem |
| **CRITICAL**     | `android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS`           | signature         |
| **CRITICAL**     | `android.permission.MOUNT_UNMOUNT_FILESYSTEMS`                  | signature         |
| **CRITICAL**     | `android.permission.PROVIDE_DEFAULT_ENABLED_CREDENTIAL_SERVICE` | signature         |
| **CRITICAL**     | `android.permission.PROVIDE_REMOTE_CREDENTIALS`                 | signature         |
| **CRITICAL**     | `android.permission.THREAD_NETWORK_PRIVILEGED`                  | signature         |
| **CRITICAL**     | `android.permission.RECORD_SENSITIVE_CONTENT`                   | signature         |
| **CRITICAL**     | `android.permission.RECEIVE_SENSITIVE_NOTIFICATIONS`            | signature         |
| **HIGH**         | `android.permission.INSTALL_GRANT_RUNTIME_PERMISSIONS`          | signature         |
| **HIGH**         | `android.permission.READ_SMS`                                   | dangerous         |
| **HIGH**         | `android.permission.WRITE_SMS`                                  | normal            |
| **HIGH**         | `android.permission.RECEIVE_MMS`                                | dangerous         |
| **HIGH**         | `android.permission.SEND_SMS_NO_CONFIRMATION`                   | signature         |
| **HIGH**         | `android.permission.RECEIVE_SMS`                                | dangerous         |
| **HIGH**         | `android.permission.READ_LOGS`                                  | signature         |
| **HIGH**         | `android.permission.READ_PRIVILEGED_PHONE_STATE`                | signature         |
| **HIGH**         | `android.permission.LOCATION_HARDWARE`                          | signature         |
| **HIGH**         | `android.permission.ACCESS_FINE_LOCATION`                       | dangerous         |
| **HIGH**         | `android.permission.ACCESS_BACKGROUND_LOCATION`                 | dangerous         |
| **HIGH**         | `android.permission.BIND_ACCESSIBILITY_SERVICE`                 | signature         |
| **HIGH**         | `android.permission.ACCESS_WIFI_STATE`                          | normal            |
| **HIGH**         | `com.android.voicemail.permission.READ_VOICEMAIL`               | signature         |
| **HIGH**         | `android.permission.RECORD_AUDIO`                               | dangerous         |
| **HIGH**         | `android.permission.CAPTURE_AUDIO_OUTPUT`                       | signature         |
| **HIGH**         | `android.permission.ACCESS_NOTIFICATIONS`                       | signature         |
| **HIGH**         | `android.permission.INTERACT_ACROSS_USERS_FULL`                 | signature         |
| **HIGH**         | `android.permission.BLUETOOTH_PRIVILEGED`                       | signature         |
| **HIGH**         | `android.permission.GET_PASSWORD`                               | signature         |
| **HIGH**         | `android.permission.INTERNAL_SYSTEM_WINDOW`                     | signature         |
| **HIGH**         | `android.permission.MANAGE_ONGOING_CALLS`                       | signature         |
| **HIGH**         | `android.permission.READ_RESTRICTED_STATS`                      | internal          |
| **HIGH**         | `android.permission.BIND_AUTOFILL_SERVICE`                      | signature         |
| **HIGH**         | `android.permission.WRITE_VERIFICATION_STATE_E2EE_CONTACT_KEYS` | signature         |
| **HIGH**         | `android.permission.READ_DROPBOX_DATA`                          | signature         |
| **HIGH**         | `android.permission.WRITE_FLAGS`                                | signature         |
| **MEDIUM**       | `android.permission.ACCESS_COARSE_LOCATION`                     | dangerous         |
| **MEDIUM**       | `android.permission.CHANGE_COMPONENT_ENABLED_STATE`             | signature         |
| **MEDIUM**       | `android.permission.READ_CONTACTS`                              | dangerous         |
| **MEDIUM**       | `android.permission.WRITE_CONTACTS`                             | dangerous         |
| **MEDIUM**       | `android.permission.CONNECTIVITY_INTERNAL`                      | signature         |
| **MEDIUM**       | `android.permission.ACCESS_MEDIA_LOCATION`                      | dangerous         |
| **MEDIUM**       | `android.permission.READ_EXTERNAL_STORAGE`                      | dangerous         |
| **MEDIUM**       | `android.permission.WRITE_EXTERNAL_STORAGE`                     | dangerous         |
| **MEDIUM**       | `android.permission.SYSTEM_ALERT_WINDOW`                        | signature         |
| **MEDIUM**       | `android.permission.READ_CALL_LOG`                              | dangerous         |
| **MEDIUM**       | `android.permission.WRITE_CALL_LOG`                             | dangerous         |
| **MEDIUM**       | `android.permission.INTERACT_ACROSS_USERS`                      | signature         |
| **MEDIUM**       | `android.permission.MANAGE_USERS`                               | signature         |
| **MEDIUM**       | `android.permission.READ_CALENDAR`                              | dangerous         |
| **MEDIUM**       | `android.permission.BLUETOOTH_ADMIN`                            | normal            |
| **MEDIUM**       | `android.permission.BODY_SENSORS`                               | dangerous         |
| **MEDIUM**       | `android.permission.MANAGE_EXTERNAL_STORAGE`                    | signature         |
| **MEDIUM**       | `android.permission.ACCESS_BLOBS_ACROSS_USERS`                  | signature         |
| **MEDIUM**       | `android.permission.BLUETOOTH_ADVERTISE`                        | dangerous         |
| **MEDIUM**       | `android.permission.READ_MEDIA_AUDIO`                           | dangerous         |
| **MEDIUM**       | `android.permission.READ_MEDIA_IMAGES`                          | dangerous         |
| **MEDIUM**       | `android.permission.READ_MEDIA_VIDEO`                           | dangerous         |
| **MEDIUM**       | `android.permission.REGISTER_NSD_OFFLOAD_ENGINE`                | signature         |
| **MEDIUM**       | `android.permission.ACCESS_LAST_KNOWN_CELL_ID`                  | signature         |
| **MEDIUM**       | `android.permission.USE_COMPANION_TRANSPORTS`                   | signature         |
| **LOW**          | `android.permission.DOWNLOAD_WITHOUT_NOTIFICATION`              | normal            |
| **LOW**          | `android.permission.PACKAGE_USAGE_STATS`                        | signature         |
| **LOW**          | `android.permission.MASTER_CLEAR`                               | signature         |
| **LOW**          | `android.permission.DELETE_PACKAGES`                            | normal            |
| **LOW**          | `android.permission.GET_PACKAGE_SIZE`                           | normal            |
| **LOW**          | `android.permission.BLUETOOTH`                                  | normal            |
| **LOW**          | `android.permission.DEVICE_POWER`                               | signature         |
| **LOW**          | `android.permission.READ_PRECISE_PHONE_STATE`                   | signature         |
| **LOW**          | `android.permission.LOG_FOREGROUND_RESOURCE_USE`                | signature         |
| **LOW**          | `android.permission.MANAGE_DEFAULT_APPLICATIONS`                | signature         |
| **LOW**          | `android.permission.MANAGE_FACE`                                | signature         |
| **LOW**          | `android.permission.REPORT_USAGE_STATS`                         | signature         |
| **LOW**          | `android.permission.MANAGE_DISPLAYS`                            | signature         |
| **LOW**          | `android.permission.RESTRICT_DISPLAY_MODES`                     | signature         |
| **LOW**          | `android.permission.ACCESS_HIDDEN_PROFILES_FULL`                | signature         |
| **LOW**          | `android.permission.GET_BACKGROUND_INSTALLED_PACKAGES`          | signature         |
| **NONE**         | `android.permission.ACCESS_NETWORK_STATE`                       | normal            |
| **NONE**         | `android.permission.RECEIVE_BOOT_COMPLETED`                     | normal            |
| **NONE**         | `android.permission.WAKE_LOCK`                                  | normal            |
| **NONE**         | `android.permission.FLASHLIGHT`                                 | normal            |
| **NONE**         | `android.permission.VIBRATE`                                    | normal            |
| **NONE**         | `android.permission.WRITE_MEDIA_STORAGE`                        | signature         |
| **NONE**         | `android.permission.MODIFY_AUDIO_SETTINGS`                      | normal            |

Note that this categorization can change over time. The paper gives us an example of that:

> Prior to Android 10, the `READ_PHONE_STATE` permission would be classified as HIGH, due to the permanent device identifiers (e.g. (IMEI/MEID, IMSI, SIM, and build serial) that it guards. However, starting from Android 10, a bulk of the sensitive information that can be used for tracking has been moved, refactored or rescoped into a new permission called `READ_PRIVILEGED_PHONE_STATE`, putting the new permission in the HIGH category, but resulting in the `READ_PHONE_STATE` permission moving to LOW.

## Permission Changes per API Level

**Android 8.0 (API level 26) Changes:**

The [following changes](https://developer.android.com/about/versions/oreo/android-8.0-changes#atap "Android 8.0 (API level 26) - Changes for all apps") affect all apps running on Android 8.0 (API level 26), even to those apps targeting lower API levels.

- **Contacts provider usage stats change**: when an app requests the [`READ_CONTACTS`](https://developer.android.com/reference/android/Manifest.permission.html#READ_CONTACTS "READ_CONTACTS") permission, queries for contact's usage data will return approximations rather than exact values (the auto-complete API is not affected by this change).

Apps targeting Android 8.0 (API level 26) or higher [are affected](https://developer.android.com/about/versions/oreo/android-8.0-changes#o-apps "Apps targeting Android 8.0") by the following:

- **Account access and discoverability improvements**: Apps can no longer get access to user accounts only by having the [`GET_ACCOUNTS`](https://developer.android.com/reference/android/Manifest.permission.html#GET_ACCOUNTS "GET_ACCOUNTS") permission granted, unless the authenticator owns the accounts or the user grants that access.
- **New telephony permissions**: the following permissions (classified as dangerous) are now part of the `PHONE` permissions group:
    - The `ANSWER_PHONE_CALLS` permission allows to answer incoming phone calls programmatically (via `acceptRingingCall`).
    - The `READ_PHONE_NUMBERS` permission grants read access to the phone numbers stored in the device.
- **Restrictions when granting dangerous permissions**: Dangerous permissions are classified into permission groups (e.g. the `STORAGE` group contains `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE`). Before Android 8.0 (API level 26), it was sufficient to request one permission of the group in order to get all permissions of that group also granted at the same time. This has changed [starting at Android 8.0 (API level 26)](https://developer.android.com/about/versions/oreo/android-8.0-changes#rmp "Android 8 Permissions Changes"): whenever an app requests a permission at runtime, the system will grant exclusively that specific permission. However, note that **all subsequent requests for permissions in that permission group will be automatically granted** without showing the permissions dialog to the user. See this example from the Android developer documentation:

    > Suppose an app lists both READ_EXTERNAL_STORAGE and WRITE_EXTERNAL_STORAGE in its manifest. The app requests READ_EXTERNAL_STORAGE and the user grants it. If the app targets API level 25 or lower, the system also grants WRITE_EXTERNAL_STORAGE at the same time, because it belongs to the same STORAGE permission group and is also registered in the manifest. If the app targets Android 8.0 (API level 26), the system grants only READ_EXTERNAL_STORAGE at that time; however, if the app later requests WRITE_EXTERNAL_STORAGE, the system immediately grants that privilege without prompting the user.

    You can see the list of permission groups in the [Android developer documentation](https://developer.android.com/guide/topics/permissions/overview.html#permission-groups "Permission groups"). To make this a bit more confusing, [Google also warns](https://developer.android.com/guide/topics/permissions/overview.html#perm-groups "Permission groups") that particular permissions might be moved from one group to another in future versions of the Android SDK and therefore, the logic of the app shouldn't rely on the structure of these permission groups. The best practice is to explicitly request every permission whenever it's needed.

**Android 9 (API Level 28) Changes:**

The [following changes](https://developer.android.com/about/versions/pie/android-9.0-changes-all "Behavior changes: all apps") affect all apps running on Android 9, even to those apps targeting API levels lower than 28.

- **Restricted access to call logs**: `READ_CALL_LOG`, `WRITE_CALL_LOG`, and `PROCESS_OUTGOING_CALLS` (dangerous) permissions are moved from `PHONE` to the new `CALL_LOG` permission group. This means that being able to make phone calls (e.g. by having the permissions of the `PHONE` group granted) is not sufficient to get access to the call logs.
- **Restricted access to phone numbers**: apps wanting to read the phone number require the `READ_CALL_LOG` permission when running on Android 9 (API level 28).
- **Restricted access to Wi-Fi location and connection information**: SSID and BSSID values cannot be retrieved (e.g. via [`WifiManager.getConnectionInfo`](https://developer.android.com/reference/android/net/wifi/WifiManager#getConnectionInfo%28%29 "WifiManager.getConnectionInfo") unless _all_ of the following is true:
    - The `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` permission.
    - The `ACCESS_WIFI_STATE` permission.
    - Location services are enabled (under **Settings** -> **Location**).

Apps targeting Android 9 (API level 28) or higher [are affected](https://developer.android.com/about/versions/pie/android-9.0-changes-28 "Behavior changes: apps targeting API level 28+") by the following:

- **Build serial number deprecation**: device's hardware serial number cannot be read (e.g. via [`Build.getSerial`](https://developer.android.com/reference/android/os/Build.html#getSerial%28%29 "getSerial")) unless the `READ_PHONE_STATE` (dangerous) permission is granted.

**Android 10 (API level 29) Changes:**

Android 10 (API level 29) introduces several [user privacy enhancements](https://developer.android.com/about/versions/10/highlights#privacy_for_users "Android 10 for Developers: Privacy for users"). The changes regarding permissions affect to all apps running on Android 10 (API level 29), including those targeting lower API levels.

- **Restricted Location access**: new permission option for location access "only while using the app".
- **Scoped storage by default**: apps targeting Android 10 (API level 29) don't need to declare any storage permission to access their files in the app specific directory in external storage as well as for files creates from the media store.
- **Restricted access to screen contents**: `READ_FRAME_BUFFER`, `CAPTURE_VIDEO_OUTPUT`, and `CAPTURE_SECURE_VIDEO_OUTPUT` permissions are now signature-access only, which prevents silent access to the device's screen contents.
- **User-facing permission check on legacy apps**: when running an app targeting Android 5.1 (API level 22) or lower for the first time, users will be prompted with a permissions screen where they can revoke access to specific _legacy permissions_ (which previously would be automatically granted at installation time).

## Permission Enforcement

**Activity Permission Enforcement:**

Permissions are applied via `android:permission` attribute within the `<activity>` tag in the manifest. These permissions restrict which applications can start that Activity. The permission is checked during `Context.startActivity` and `Activity.startActivityForResult`. Not holding the required permission results in a `SecurityException` being thrown from the call.

**Service Permission Enforcement:**

Permissions applied via `android:permission` attribute within the `<service>` tag in the manifest restrict who can start or bind to the associated Service. The permission is checked during `Context.startService`, `Context.stopService` and `Context.bindService`. Not holding the required permission results in a `SecurityException` being thrown from the call.

**Broadcast Permission Enforcement:**

Permissions applied via `android:permission` attribute within the `<receiver>` tag restrict access to send broadcasts to the associated `BroadcastReceiver`. The held permissions are checked after `Context.sendBroadcast` returns, while trying to deliver the sent broadcast to the given receiver. Not holding the required permissions doesn't throw an exception, the result is an unsent broadcast.

A permission can be supplied to `Context.registerReceiver` to control who can broadcast to a programmatically registered receiver. Going the other way, a permission can be supplied when calling `Context.sendBroadcast` to restrict which broadcast receivers are allowed to receive the broadcast.

Note that both a receiver and a broadcaster can require a permission. When this happens, both permission checks must pass for the intent to be delivered to the associated target. For more information, please reference the section ["Restricting broadcasts with permissions"](https://developer.android.com/guide/components/broadcasts#restrict-broadcasts-permissions "Restricting broadcasts with permissions") in the Android Developers Documentation.

**Content Provider Permission Enforcement:**

Permissions applied via `android:permission` attribute within the `<provider>` tag restrict access to data in a ContentProvider. Content providers have an important additional security facility called URI permissions which is described next. Unlike the other components, ContentProviders have two separate permission attributes that can be set, `android:readPermission` restricts who can read from the provider, and `android:writePermission` restricts who can write to it. If a ContentProvider is protected with both read and write permissions, holding only the write permission does not also grant read permissions.

Permissions are checked when you first retrieve a provider and as operations are performed using the ContentProvider. Using `ContentResolver.query` requires holding the read permission; using `ContentResolver.insert`, `ContentResolver.update`, `ContentResolver.delete` requires the write permission. A `SecurityException` will be thrown from the call if proper permissions are not held in all these cases.

**Content Provider URI Permissions:**

The standard permission system is not sufficient when being used with content providers. For example a content provider may want to limit permissions to READ permissions in order to protect itself, while using custom URIs to retrieve information. An application should only have the permission for that specific URI.

The solution is per-URI permissions. When starting or returning a result from an activity, the method can set `Intent.FLAG_GRANT_READ_URI_PERMISSION` and/or `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`. This grants permission to the activity for
the specific URI regardless if it has permissions to access to data from the content provider.

This allows a common capability-style model where user interaction drives ad-hoc granting of fine-grained permission. This can be a key facility for reducing the permissions needed by apps to only those directly related to their behavior. Without this model in place malicious users may access other member's email attachments or harvest contact lists for future use via unprotected URIs. In the manifest the [`android:grantUriPermissions`](https://developer.android.com/guide/topics/manifest/provider-element#gprmsn "android:grantUriPermissions") attribute or the node help restrict the URIs.

Here you can find more information about APIs related to URI Permissions:

- [grantUriPermission](https://developer.android.com/reference/android/content/Context.html#grantUriPermission%28java.lang.String,%20android.net.Uri,%20int%29 "grantUriPermission")
- [revokeUriPermission](https://developer.android.com/reference/android/content/Context#revokeUriPermission%28android.net.Uri,%20int%29 "revokeUriPermission")
- [checkUriPermission](https://developer.android.com/reference/android/content/Context#checkUriPermission%28android.net.Uri,%20int,%20int,%20int%29 "checkUriPermission")

## Custom Permissions

Android allows apps to expose their services/components to other apps. Custom permissions are required for app access to the exposed components. You can define [custom permissions](https://developer.android.com/guide/topics/permissions/defining.html "Custom Permissions") in `AndroidManifest.xml` by creating a permission tag with two mandatory attributes: `android:name` and `android:protectionLevel`.

It is crucial to create custom permissions that adhere to the _Principle of Least Privilege_: permission should be defined explicitly for its purpose, with a meaningful and accurate label and description.

Below is an example of a custom permission called `START_MAIN_ACTIVITY`, which is required when launching the `TEST_ACTIVITY` Activity.

The first code block defines the new permission, which is self-explanatory. The label tag is a summary of the permission, and the description is a more detailed version of the summary. You can set the protection level according to the types of permissions that will be granted. Once you've defined your permission, you can enforce it by adding it to the application's manifest. In our example, the second block represents the component that we are going to restrict with the permission we created. It can be enforced by adding the `android:permission` attributes.

```xml
<permission android:name="com.example.myapp.permission.START_MAIN_ACTIVITY"
        android:label="Start Activity in myapp"
        android:description="Allow the app to launch the activity of myapp app, any app you grant this permission will be able to launch main activity by myapp app."
        android:protectionLevel="normal" />

<activity android:name="TEST_ACTIVITY"
    android:permission="com.example.myapp.permission.START_MAIN_ACTIVITY">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
     </intent-filter>
</activity>
```

Once the permission `START_MAIN_ACTIVITY` has been created, apps can request it via the `uses-permission` tag in the `AndroidManifest.xml` file. Any application granted the custom permission `START_MAIN_ACTIVITY` can then launch the `TEST_ACTIVITY`. Please note `<uses-permission android:name="myapp.permission.START_MAIN_ACTIVITY" />` must be declared before the `<application>` or an exception will occur at runtime. Please see the example below that is based on the [permission overview](https://developer.android.com/guide/topics/permissions/overview "permission overview") and [manifest-intro](https://developer.android.com/guide/topics/manifest/manifest-intro#filestruct "manifest-intro").

```xml
<manifest>
<uses-permission android:name="com.example.myapp.permission.START_MAIN_ACTIVITY" />
        <application>
            <activity>
            </activity>
        </application>
</manifest>
```

We recommend using a reverse-domain annotation when registering a permission, as in the example above (e.g. `com.domain.application.permission`) in order to avoid collisions with other applications.
