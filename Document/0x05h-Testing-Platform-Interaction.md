# Android Platform APIs

## Testing App Permissions (MSTG-PLATFORM-1)

### Overview

Android assigns a distinct system identity (Linux user ID and group ID) to every installed app. Because each Android app operates in a process sandbox, apps must explicitly request access to resources and data that are outside their sandbox. They request this access by declaring the permissions they need to use system data and features. Depending on how sensitive or critical the data or feature is, the Android system will grant the permission automatically or ask the user to approve the request.

Android permissions are classified into four different categories on the basis of the protection level they offer:

- **Normal**: This permission gives apps access to isolated application-level features with minimal risk to other apps, the user, and the system. For apps targeting Android 6.0 (API level 23) or higher, these permissions are granted automatically at installation time. For apps targeting a lower API level, the user needs to approve them at installation time. Example: `android.permission.INTERNET`.
- **Dangerous**: This permission usually gives the app control over user data or control over the device in a way that impacts the user. This type of permission may not be granted at installation time; whether the app should have the permission may be left for the user to decide. Example: `android.permission.RECORD_AUDIO`.
- **Signature**: This permission is granted only if the requesting app was signed with the same certificate used to sign the app that declared the permission. If the signature matches, the permission will be granted automatically. This permission is granted at installation time. Example: `android.permission.ACCESS_MOCK_LOCATION`.
- **SystemOrSignature**: This permission is granted only to applications embedded in the system image or signed with the same certificate used to sign the application that declared the permission. Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`.

A list of all permissions can be found in the [Android developer documentation](https://developer.android.com/guide/topics/permissions/overview.html "Permissions overview") as well as concrete steps on how to:

- [Declare app permissions](https://developer.android.com/training/permissions/declaring) in your app's manifest file.
- [Request app permissions](https://developer.android.com/training/permissions/requesting) programmatically.
- [Define a Custom App Permission](https://developer.android.com/guide/topics/permissions/defining) to share your app resources and capabilities with other apps.

#### Android 8.0 (API level 26) Changes

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

#### Android 9 (API Level 28) Changes

The [following changes](https://developer.android.com/about/versions/pie/android-9.0-changes-all "Behavior changes: all apps") affect all apps running on Android 9, even to those apps targeting API levels lower than 28.

- **Restricted access to call logs**: `READ_CALL_LOG`, `WRITE_CALL_LOG`, and `PROCESS_OUTGOING_CALLS` (dangerous) permissions are moved from `PHONE` to the new `CALL_LOG` permission group. This means that being able to make phone calls (e.g. by having the permissions of the `PHONE` group granted) is not sufficient to get access to the call logs.
- **Restricted access to phone numbers**: apps wanting to read the phone number require the `READ_CALL_LOG` permission when running on Android 9 (API level 28).
- **Restricted access to Wi-Fi location and connection information**: SSID and BSSID values cannot be retrieved (e.g. via [`WifiManager.getConnectionInfo`](https://developer.android.com/reference/android/net/wifi/WifiManager#getConnectionInfo%28%29 "WifiManager.getConnectionInfo") unless _all_ of the following is true:
  - The `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` permission.
  - The `ACCESS_WIFI_STATE` permission.
  - Location services are enabled (under **Settings** -> **Location**).

Apps targeting Android 9 (API level 28) or higher [are affected](https://developer.android.com/about/versions/pie/android-9.0-changes-28 "Behavior changes: apps targeting API level 28+") by the following:

- **Build serial number deprecation**: device's hardware serial number cannot be read (e.g. via [`Build.getSerial`](https://developer.android.com/reference/android/os/Build.html#getSerial%28%29 "getSerial")) unless the `READ_PHONE_STATE` (dangerous) permission is granted.

#### Android 10 Changes (Beta)

Android 10 Beta introduces several [user privacy enhancements](https://developer.android.com/preview/privacy/permissions "Android Q privacy: Changes to permissions"). The changes regarding permissions affect to all apps running on Android 10, including those targeting lower API levels.

- **Restricted access to screen contents**: `READ_FRAME_BUFFER`, `CAPTURE_VIDEO_OUTPUT`, and `CAPTURE_SECURE_VIDEO_OUTPUT` permissions are now signature-access only, which prevents silent access to the device's screen contents.
- **User-facing permission check on legacy apps**: when running an app targeting Android 5.1 (API level 22) or lower for the first time, users will be prompted with a permissions screen where they can revoke access to specific _legacy permissions_ (which previously would be automatically granted at installation time).

### Activity Permission Enforcement

Permissions are applied via `android:permission` attribute within the `<activity>` tag in the manifest. These permissions restrict which applications can start that Activity. The permission is checked during `Context.startActivity` and `Activity.startActivityForResult`. Not holding the required permission results in a `SecurityException` being thrown from the call.

### Service Permission Enforcement

Permissions applied via `android:permission` attribute within the `<service>` tag in the manifest restrict who can start or bind to the associated Service. The permission is checked during `Context.startService`, `Context.stopService` and `Context.bindService`. Not holding the required permission results in a `SecurityException` being thrown from the call.

### Broadcast Permission Enforcement

Permissions applied via `android:permission` attribute within the `<receiver>` tag restrict access to send broadcasts to the associated `BroadcastReceiver`. The held permissions are checked after `Context.sendBroadcast` returns, while trying to deliver the sent broadcast to the given receiver. Not holding the required permissions doesn't throw an exception, the result is an unsent broadcast.

A permission can be supplied to `Context.registerReceiver` to control who can broadcast to a programmatically registered receiver. Going the other way, a permission can be supplied when calling `Context.sendBroadcast` to restrict which broadcast receivers are allowed to receive the broadcast.

Note that both a receiver and a broadcaster can require a permission. When this happens, both permission checks must pass for the intent to be delivered to the associated target. For more information, please reference the section "[Restricting broadcasts with permissions](https://developer.android.com/guide/components/broadcasts#restrict-broadcasts-permissions "Restricting broadcasts with permissions")" in the Android Developers Documentation.

### Content Provider Permission Enforcement

Permissions applied via `android:permission` attribute within the `<provider>` tag restrict access to data in a ContentProvider. Content providers have an important additional security facility called URI permissions which is described next. Unlike the other components, ContentProviders have two separate permission attributes that can be set, `android:readPermission` restricts who can read from the provider, and `android:writePermission` restricts who can write to it. If a ContentProvider is protected with both read and write permissions, holding only the write permission does not also grant read permissions.

Permissions are checked when you first retrieve a provider and as operations are performed using the ContentProvider. Using `ContentResolver.query` requires holding the read permission; using `ContentResolver.insert`, `ContentResolver.update`, `ContentResolver.delete` requires the write permission. A `SecurityException` will be thrown from the call if proper permissions are not held in all these cases.

### Content Provider URI Permissions

The standard permission system is not sufficient when being used with content providers. For example a content provider may want to limit permissions to READ permissions in order to protect itself, while using custom URIs to retrieve information. An application should only have the permission for that specific URI.

The solution is per-URI permissions. When starting or returning a result from an activity, the method can set `Intent.FLAG_GRANT_READ_URI_PERMISSION` and/or `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`. This grants permission to the activity for
the specific URI regardless if it has permissions to access to data from the content provider.

This allows a common capability-style model where user interaction drives ad-hoc granting of fine-grained permission. This can be a key facility for reducing the permissions needed by apps to only those directly related to their behavior. Without this model in place malicious users may access other member's email attachments or harvest contact lists for future use via unprotected URIs. In the manifest the [`android:grantUriPermissions`](https://developer.android.com/guide/topics/manifest/provider-element#gprmsn "android:grantUriPermissions") attribute or the node help restrict the URIs.

### Documentation for URI Permissions

- [grantUriPermission](https://developer.android.com/reference/android/content/Context.html#grantUriPermission%28java.lang.String,%20android.net.Uri,%20int%29 "grantUriPermission")
- [revokeUriPermission](https://developer.android.com/reference/android/content/Context#revokeUriPermission%28android.net.Uri,%20int%29 "revokeUriPermission")
- [checkUriPermission](https://developer.android.com/reference/android/content/Context#checkUriPermission%28android.net.Uri,%20int,%20int,%20int%29 "checkUriPermission")

#### Custom Permissions

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

### Static Analysis

#### Android Permissions

Check permissions to make sure that the app really needs them and remove unnecessary permissions. For example, the `INTERNET` permission in the AndroidManifest.xml file is necessary for an Activity to load a web page into a WebView. Because a user can revoke an application's right to use a dangerous permission, the developer should check whether the application has the appropriate permission each time an action is performed that would require that permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Go through the permissions with the developer to identify the purpose of every permission set and remove unnecessary permissions.

Besides going through the AndroidManifest.xml file manually, you can also use the Android Asset Packaging tool (aapt) to examine the permissions of an APK file.

> aapt comes with the Android SDK within the build-tools folder. It requires an APK file as input. You may list the APKs in the device by running `adb shell pm list packages -f | grep -i <keyword>` as seen in "[Listing Installed Apps](0x05b-Basic-Security_Testing.md#listing-installed-apps "Listing Installed Apps")".

```bash
$ aapt d permissions app-x86-debug.apk
package: sg.vp.owasp_mobile.omtg_android
uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
uses-permission: name='android.permission.INTERNET'
```

Alternatively you may obtain a more detailed list of permissions via adb and the dumpsys tool:

```bash
$ adb shell dumpsys package sg.vp.owasp_mobile.omtg_android | grep permission
    requested permissions:
      android.permission.WRITE_EXTERNAL_STORAGE
      android.permission.INTERNET
      android.permission.READ_EXTERNAL_STORAGE
    install permissions:
      android.permission.INTERNET: granted=true
      runtime permissions:
```

Please reference this [permissions overview](https://developer.android.com/guide/topics/permissions/overview#permission-groups "Table 1. Dangerous permissions and permission groups.") for descriptions of the listed permissions that are considered dangerous.

```default
READ_CALENDAR
WRITE_CALENDAR
READ_CALL_LOG
WRITE_CALL_LOG
PROCESS_OUTGOING_CALLS
CAMERA
READ_CONTACTS
WRITE_CONTACTS
GET_ACCOUNTS
ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION
RECORD_AUDIO
READ_PHONE_STATE
READ_PHONE_NUMBERS
CALL_PHONE
ANSWER_PHONE_CALLS
ADD_VOICEMAIL
USE_SIP
BODY_SENSORS
SEND_SMS
RECEIVE_SMS
READ_SMS
RECEIVE_WAP_PUSH
RECEIVE_MMS
READ_EXTERNAL_STORAGE
WRITE_EXTERNAL_STORAGE
```

#### Custom Permissions

Apart from enforcing custom permissions via the application manifest file, you can also check permissions programmatically. This is not recommended, however, because it is more error-prone and can be bypassed more easily with, e.g., runtime instrumentation. It is recommended that the `ContextCompat.checkSelfPermission` method is called to check if an activity has a specified permission. Whenever you see code like the following snippet, make sure that the same permissions are enforced in the manifest file.

```java
private static final String TAG = "LOG";
int canProcess = checkCallingOrSelfPermission("com.example.perm.READ_INCOMING_MSG");
if (canProcess != PERMISSION_GRANTED)
throw new SecurityException();
```

Or with `ContextCompat.checkSelfPermission` which compares it to the manifest file.

```java
if (ContextCompat.checkSelfPermission(secureActivity.this, Manifest.READ_INCOMING_MSG)
        != PackageManager.PERMISSION_GRANTED) {
            //!= stands for not equals PERMISSION_GRANTED
            Log.v(TAG, "Permission denied");
        }
```

### Requesting Permissions

If your application has permissions that need to be requested at runtime, the application must call the `requestPermissions` method in order to obtain them. The app passes the permissions needed and an integer request code you have specified to the user asynchronously, returning once the user chooses to accept or deny the request in the same thread. After the response is returned the same request code is passed to the app's callback method.

```java
private static final String TAG = "LOG";
// We start by checking the permission of the current Activity
if (ContextCompat.checkSelfPermission(secureActivity.this,
        Manifest.permission.WRITE_EXTERNAL_STORAGE)
        != PackageManager.PERMISSION_GRANTED) {

    // Permission is not granted
    // Should we show an explanation?
    if (ActivityCompat.shouldShowRequestPermissionRationale(secureActivity.this,
        //Gets whether you should show UI with rationale for requesting permission.
        //You should do this only if you do not have permission and the permission requested rationale is not communicated clearly to the user.
            Manifest.permission.WRITE_EXTERNAL_STORAGE)) {
        // Asynchronous thread waits for the users response.
        // After the user sees the explanation try requesting the permission again.
    } else {
        // Request a permission that doesn't need to be explained.
        ActivityCompat.requestPermissions(secureActivity.this,
                new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
        // MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE will be the app-defined int constant.
        // The callback method gets the result of the request.
    }
} else {
    // Permission already granted debug message printed in terminal.
    Log.v(TAG, "Permission already granted.");
}
```

Please note that if you need to provide any information or explanation to the user it needs to be done before the call to `requestPermissions`, since the system dialog box can not be altered once called.

### Handling Responses to Permission Requests

Now your app has to override the system method `onRequestPermissionsResult` to see if the permission was granted. This method receives the `requestCode` integer as input parameter (which is the same request code that was created in `requestPermissions`).

The following callback method may be used for `WRITE_EXTERNAL_STORAGE`.

```java
@Override //Needed to override system method onRequestPermissionsResult()
public void onRequestPermissionsResult(int requestCode, //requestCode is what you specified in requestPermissions()
        String permissions[], int[] permissionResults) {
    switch (requestCode) {
        case MY_PERMISSIONS_WRITE_EXTERNAL_STORAGE: {
            if (grantResults.length > 0
                && permissionResults[0] == PackageManager.PERMISSION_GRANTED) {
                // 0 is a canceled request, if int array equals requestCode permission is granted.
            } else {
                // permission denied code goes here.
                Log.v(TAG, "Permission denied");
            }
            return;
        }
        // Other switch cases can be added here for multiple permission checks.
    }
}

```

Permissions should be explicitly requested for every needed permission, even if a similar permission from the same group has already been requested. For applications targeting Android 7.1 (API level 25) and older, Android will automatically give an application all the permissions from a permission group, if the user grants one of the requested permissions of that group. Starting with Android 8.0 (API level 26), permissions will still automatically be granted if a user has already granted a permission from the same permission group, but the application still needs to explicitly request the permission. In this case, the `onRequestPermissionsResult` handler will automatically be triggered without any user interaction.

For example if both `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE` are listed in the Android Manifest but only permissions are granted for `READ_EXTERNAL_STORAGE`, then requesting `WRITE_EXTERNAL_STORAGE` will automatically have permissions without user interaction because they are in the same group and not explicitly requested.

### Permission Analysis

Always check whether the application is requesting permissions it actually requires. Make sure that no permissions are requested which are not related to the goal of the app, especially `DANGEROUS` and `SIGNATURE` permissions, since they can affect both the user and the application if mishandled. For instance, it should be suspicious if a single-player game app requires access to `android.permission.WRITE_SMS`.

When analyzing permissions, you should investigate the concrete use case scenarios of the app and always check if there are replacement APIs for any `DANGEROUS` permissions in use. A good example is the [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview) which streamlines the usage of SMS permissions when performing SMS-based user verification. By using this API an application does not have to declare `DANGEROUS` permissions which is a benefit to both the user and developers of the application, who doesn't have to submit the [Permissions Declaration Form](https://support.google.com/googleplay/android-developer/answer/9214102?hl=en).

### Dynamic Analysis

Permissions for installed applications can be retrieved with `adb`. The following extract demonstrates how to examine the permissions used by an application.

```bash
$ adb shell dumpsys package com.google.android.youtube
...
declared permissions:
  com.google.android.youtube.permission.C2D_MESSAGE: prot=signature, INSTALLED
requested permissions:
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
install permissions:
  com.google.android.c2dm.permission.RECEIVE: granted=true
  android.permission.USE_CREDENTIALS: granted=true
  com.google.android.providers.gsf.permission.READ_GSERVICES: granted=true  
...
```

The output shows all permissions using the following categories:

- **declared permissions**: list of all _custom_ permissions.
- **requested and install permissions**: list of all install-time permissions including _normal_ and _signature_ permissions.
- **runtime permissions**: list of all _dangerous_ permissions.

When doing the dynamic analysis:

- [Evaluate](https://developer.android.com/training/permissions/evaluating) whether the app really needs the requested permissions. For instance: a single-player game that requires access to `android.permission.WRITE_SMS`, might not be a good idea.
- In many cases the app could opt for [alternatives to declaring permissions](https://developer.android.com/training/permissions/evaluating#alternatives), such as:
  - requesting the `ACCESS_COARSE_LOCATION` permission instead of `ACCESS_FINE_LOCATION`. Or even better not requesting the permission at all, and instead ask the user to enter a postal code.
  - invoking the `ACTION_IMAGE_CAPTURE` or `ACTION_VIDEO_CAPTURE` intent action instead of requesting the `CAMERA` permission.
  - using [Companion Device Pairing](https://developer.android.com/guide/topics/connectivity/companion-device-pairing) (Android 8.0 (API level 26) and higher) when pairing with a Bluetooth device instead of declaring the `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATIION`, or `BLUETOOTH_ADMIN` permissions.
- Use the [Privacy Dashboard](https://developer.android.com/training/permissions/explaining-access#privacy-dashboard) (Android 12 (API level 31) and higher) to verify how the app [explains access to sensitive information](https://developer.android.com/training/permissions/explaining-access).

To obtain detail about a specific permission you can refer to the [Android Documentation](https://developer.android.com/reference/android/Manifest.permission).

## Testing for Injection Flaws (MSTG-PLATFORM-2)

### Overview

Android apps can expose functionality through deep links (which are a part of Intents). They can expose functionality to:

- other apps (via deep links or other IPC mechanisms, such as Intents or BroadcastReceivers).
- the user (via the user interface).

None of the input from these sources can be trusted; it must be validated and/or sanitized. Validation ensures processing of data that the app is expecting only. If validation is not enforced, any input can be sent to the app, which may allow an attacker or malicious app to exploit app functionality.

The following portions of the source code should be checked if any app functionality has been exposed:

- Deep Links. Check the test case ["Testing Deep Links"](#testing-deep-links-mstg-platform-3) as well for further test scenarios.
- IPC Mechanisms (Intents, Binders, Android Shared Memory, or BroadcastReceivers). Check the test case ["Testing for Sensitive Functionality Exposure Through IPC"](#testing-for-sensitive-functionality-exposure-through-ipc-mstg-platform-4) as well for further test scenarios.
- User interface. Check the test case ["Testing for Overlay Attacks"](#testing-for-overlay-attacks-mstg-platform-9).

An example of a vulnerable IPC mechanism is shown below.

You can use _ContentProviders_ to access database information, and you can probe services to see if they return data. If data is not validated properly, the content provider may be prone to SQL injection while other apps are interacting with it. See the following vulnerable implementation of a _ContentProvider_.

```xml
<provider
    android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"
    android:authorities="sg.vp.owasp_mobile.provider.College">
</provider>
```

The `AndroidManifest.xml` above defines a content provider that's exported and therefore available to all other apps. The `query` function in the `OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java` class should be inspected.

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,String[] selectionArgs, String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables(STUDENTS_TABLE_NAME);

    switch (uriMatcher.match(uri)) {
        case STUDENTS:
            qb.setProjectionMap(STUDENTS_PROJECTION_MAP);
            break;

        case STUDENT_ID:
            // SQL Injection when providing an ID
            qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));
            Log.e("appendWhere",uri.getPathSegments().get(1).toString());
            break;

        default:
            throw new IllegalArgumentException("Unknown URI " + uri);
    }

    if (sortOrder == null || sortOrder == ""){
        /**
         * By default sort on student names
         */
        sortOrder = NAME;
    }
    Cursor c = qb.query(db, projection, selection, selectionArgs,null, null, sortOrder);

    /**
     * register to watch a content URI for changes
     */
    c.setNotificationUri(getContext().getContentResolver(), uri);
    return c;
}
```

While the user is providing a STUDENT_ID at `content://sg.vp.owasp_mobile.provider.College/students`, the query statement is prone to SQL injection. Obviously [prepared statements](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html "OWASP SQL Injection Prevention Cheat Sheet") must be used to avoid SQL injection, but [input validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html "OWASP Input Validation Cheat Sheet") should also be applied so that only input that the app is expecting is processed.

All app functions that process data coming in through the UI should implement input validation:

- For user interface input, [Android Saripaar v2](https://github.com/ragunathjawahar/android-saripaar "Android Saripaar v2") can be used.
- For input from IPC or URL schemes, a validation function should be created. For example, the following determines whether the [string is alphanumeric](https://stackoverflow.com/questions/11241690/regex-for-checking-if-a-string-is-strictly-alphanumeric "Input Validation"):

```java
public boolean isAlphaNumeric(String s){
    String pattern= "^[a-zA-Z0-9]*$";
    return s.matches(pattern);
}
```

An alternative to validation functions is type conversion, with, for example, `Integer.parseInt` if only integers are expected. The [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html "OWASP Input Validation Cheat Sheet") contains more information about this topic.

### Dynamic Analysis

The tester should manually test the input fields with strings like `OR 1=1--` if, for example, a local SQL injection vulnerability has been identified.

On a rooted device, the command content can be used to query the data from a content provider. The following command queries the vulnerable function described above.

```bash
# content query --uri content://sg.vp.owasp_mobile.provider.College/students
```

SQL injection can be exploited with the following command. Instead of getting the record for Bob only, the user can retrieve all data.

```bash
# content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```

## Testing for Fragment Injection (MSTG-PLATFORM-2)

### Overview

Android SDK offers developers a way to present a [`Preferences activity`](https://developer.android.com/reference/android/preference/PreferenceActivity.html "Preference Activity") to users, allowing the developers to extend and adapt this abstract class.

This abstract class parses the extra data fields of an Intent, in particular, the `PreferenceActivity.EXTRA_SHOW_FRAGMENT(:android:show_fragment)` and `Preference Activity.EXTRA_SHOW_FRAGMENT_ARGUMENTS(:android:show_fragment_arguments)` fields.

The first field is expected to contain the `Fragment` class name, and the second one is expected to contain the input bundle passed to the `Fragment`.

Because the `PreferenceActivity` uses reflection to load the fragment, an arbitrary class may be loaded inside the package or the Android SDK. The loaded class runs in the context of the application that exports this activity.

With this vulnerability, an attacker can call fragments inside the target application or run the code present in other classes' constructors. Any class that's passed in the Intent and does not extend the Fragment class will cause a `java.lang.CastException`, but the empty constructor will be executed before the exception is thrown, allowing the code present in the class constructor run.

To prevent this vulnerability, a new method called `isValidFragment` was added in Android 4.4 (API level 19). It allows developers to override this method and define the fragments that may be used in this context.

The default implementation returns `true` on versions older than Android 4.4 (API level 19); it will throw an exception on later versions.

### Static Analysis

Steps:

- Check if `android:targetSdkVersion` less than 19.
- Find exported Activities that extend the `PreferenceActivity` class.
- Determine whether the method `isValidFragment` has been overridden.
- If the app currently sets its `android:targetSdkVersion` in the manifest to a value less than 19 and the vulnerable class does not contain any implementation of `isValidFragment` then, the vulnerability is inherited from the `PreferenceActivity`.
- In order to fix, developers should either update the `android:targetSdkVersion` to 19 or higher. Alternatively, if the `android:targetSdkVersion` cannot be updated, then developers should implement `isValidFragment` as described.

The following example shows an Activity that extends this activity:

```java
public class MyPreferences extends PreferenceActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
```

The following examples show the `isValidFragment` method being overridden with an implementation that allows the loading of `MyPreferenceFragment` only:

```java
@Override
protected boolean isValidFragment(String fragmentName)
{
return "com.fullpackage.MyPreferenceFragment".equals(fragmentName);
}

```

### Example of Vulnerable App and Exploitation

MainActivity.class

```java
public class MainActivity extends PreferenceActivity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
```

MyFragment.class

```java
public class MyFragment extends Fragment {
    public void onCreate (Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragmentLayout, null);
        WebView myWebView = (WebView) wv.findViewById(R.id.webview);
        myWebView.getSettings().setJavaScriptEnabled(true);
        myWebView.loadUrl(this.getActivity().getIntent().getDataString());
        return v;
    }
}
```

To exploit this vulnerable Activity, you can create an application with the following code:

```java
Intent i = new Intent();
i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
i.setClassName("pt.claudio.insecurefragment","pt.claudio.insecurefragment.MainActivity");
i.putExtra(":android:show_fragment","pt.claudio.insecurefragment.MyFragment");
i.setData(Uri.parse("https://security.claudio.pt"));
startActivity(i);
```

The [Vulnerable App](https://github.com/clviper/android-fragment-injection/raw/master/vulnerableapp.apk "Vulnerable App Fragment Injection") and [Exploit PoC App](https://github.com/clviper/android-fragment-injection/blob/master/exploit.apk "PoC App to exploit Fragment Injection") are available for downloading.

## Testing for URL Loading in WebViews (MSTG-PLATFORM-2)

### Overview

WebViews are Android's embedded components which allow your app to open web pages within your application. In addition to mobile apps related threats, WebViews may expose your app to common web threats (e.g. XSS, Open Redirect, etc.).

One of the most important things to do when testing WebViews is to make sure that only trusted content can be loaded in it. Any newly loaded page could be potentially malicious, try to exploit any WebView bindings or try to phish the user. Unless you're developing a browser app, usually you'd like to restrict the pages being loaded to the domain of your app. A good practice is to prevent the user from even having the chance to input any URLs inside WebViews (which is the default on Android) nor navigate outside the trusted domains. Even when navigating on trusted domains there's still the risk that the user might encounter and click on other links to untrustworthy content (e.g. if the page allows for other users to post comments). In addition, some developers might even override some default behavior which can be potentially dangerous for the user. See the Static Analysis section below for more details.

#### SafeBrowsing API

To provide a safer web browsing experience, Android 8.1 (API level 27) introduces the [`SafeBrowsing API`](https://developers.google.com/safe-browsing/v4), which allows your application to detect URLs that Google has classified as a known threat.

By default, WebViews show a warning to users about the security risk with the option to load the URL or stop the page from loading. With the SafeBrowsing API you can customize your application's behavior by either reporting the threat to SafeBrowsing or performing a particular action such as returning back to safety each time it encounters a known threat. Please check the [Android Developers documentation](https://developer.android.com/about/versions/oreo/android-8.1#safebrowsing) for usage examples.

You can use the SafeBrowsing API independently from WebViews using the [SafetyNet library](https://developer.android.com/training/safetynet/safebrowsing), which implements a client for Safe Browsing Network Protocol v4. SafetyNet allows you to analyze all the URLs that your app is supposed load. You can check URLs with different schemes (e.g. http, file) since SafeBrowsing is agnostic to URL schemes, and against `TYPE_POTENTIALLY_HARMFUL_APPLICATION` and `TYPE_SOCIAL_ENGINEERING` threat types.

#### Virus Total API

Virus Total provides an API for analyzing URLs and local files for known threats. The API Reference is available on [Virus Total developers page](https://developers.virustotal.com/reference#getting-started "Getting Started").

> When sending URLs or files to be checked for known threats make sure they don't contain sensitive data which could compromise a user's privacy, or expose sensitive content from your application.

### Static Analysis

As we mentioned before, [handling page navigation](https://developer.android.com/guide/webapps/webview#HandlingNavigation "Handling page navigation") should be analyzed carefully, especially when users might be able to navigate away from a trusted environment. The default and safest behavior on Android is to let the default web browser open any link that the user might click inside the WebView. However, this default logic can be modified by configuring a `WebViewClient` which allows navigation requests to be handled by the app itself. If this is the case, be sure to search for and inspect the following interception callback functions:

- `shouldOverrideUrlLoading` allows your application to either abort loading WebViews with suspicious content by returning `true` or allow the WebView to load the URL by returning `false`. Considerations:
  - This method is not called for POST requests.
  - This method is not called for XmlHttpRequests, iFrames, "src" attributes included in HTML or `<script>` tags. Instead, `shouldInterceptRequest` should take care of this.
- `shouldInterceptRequest` allows the application to return the data from resource requests. If the return value is null, the WebView will continue to load the resource as usual. Otherwise, the data returned by the `shouldInterceptRequest` method is used. Considerations:
  - This callback is invoked for a variety of URL schemes (e.g., `http(s):`, `data:`, `file:`, etc.), not only those schemes which send requests over the network.
  - This is not called for `javascript:` or `blob:` URLs, or for assets accessed via `file:///android_asset/` or `file:///android_res/` URLs.
In the case of redirects, this is only called for the initial resource URL, not any subsequent redirect URLs.
  - When Safe Browsing is enabled, these URLs still undergo Safe Browsing checks but the developer can allow the URL with `setSafeBrowsingWhitelist` or even ignore the warning via the `onSafeBrowsingHit` callback.
  
As you can see there are a lot of points to consider when testing the security of WebViews that have a WebViewClient configured, so be sure to carefully read and understand all of them by checking the [`WebViewClient` Documentation](https://developer.android.com/reference/android/webkit/WebViewClient "WebViewClient").

While the default value of `EnableSafeBrowsing` is `true`, some applications might opt to disable it. To verify that SafeBrowsing is enabled, inspect the AndroidManifest.xml file and make sure that the configuration below is not present:

```xml
<manifest>
    <application>
        <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
                   android:value="false" />
        ...
    </application>
</manifest>
```

### Dynamic Analysis

A convenient way to dynamically test deep linking is to use Frida or frida-trace and hook the `shouldOverrideUrlLoading`, `shouldInterceptRequest` methods while using the app and clicking on links within the WebView. Be sure to also hook other related [`Uri`](https://developer.android.com/reference/android/net/Uri "Uri class") methods such as `getHost`, `getScheme` or `getPath` which are typically used to inspect the requests and match known patterns or deny lists.

## Testing Deep Links (MSTG-PLATFORM-3)

### Overview

_Deep links_ are URIs of any scheme that take users directly to specific content in an app. An app can [set up deep links](https://developer.android.com/training/app-links/deep-linking) by adding _intent filters_ on the Android Manifest and extracting data from incoming intents to navigate users to the correct activity.

Android supports two types of deep links:

- **Custom URL Schemes**, which are deep links that use any custom URL scheme, e.g. `myapp://` (not verified by the OS).
- **Android App Links** (Android 6.0 (API level 23) and higher), which are deep links that use the `http://` and `https://` schemes and contain the `autoVerify` attribute (which triggers OS verification).

#### Deep Link Collision

Using unverified deep links can cause a significant issue- any other apps installed on a user's device can declare and try to handle the same intent, which is known as **deep link collision**. Any arbitrary application can declare control over the exact same deep link belonging to another application.

In recent versions of Android this results in a so-called _disambiguation dialog_ shown to the user that asks them to select the application that should handle the deep link. The user could make the mistake of choosing a malicious application instead of the legitimate one.

![OWASP_MSTG](https://developer.android.com/training/app-links/images/app-disambiguation_2x.png)

#### Android App Links

In order to solve the deep link collision issue, Android 6.0 (API Level 23) introduced [**Android App Links**](https://developer.android.com/training/app-links), which are [verified deep links](https://developer.android.com/training/app-links/verify-site-associations "Verify Android App Links") based on a website URL explicitly registered by the developer. Clicking on an App Link will immediately open the app if it's installed.

There are some key differences from unverified deep links:

- App Links only use `http://` and `https://` schemes, any other custom URL schemes are not allowed.
- App Links require a live domain to serve a [Digital Asset Links file](https://developers.google.com/digital-asset-links/v1/getting-started "Digital Asset Link") via HTTPS.
- App Links do not suffer from deep link collision since they don't show a disambiguation dialog when a user opens them.

#### Testing Deep Links

Any existing deep links (including App Links) can potentially increase the app attack surface. This [includes many risks](https://people.cs.vt.edu/gangwang/deep17.pdf) such as link hijacking, sensitive functionality exposure, etc. The Android version in which the app runs also influences the risk:

- Before Android 12 (API level 31), if the app has any [non-verifiable links](https://developer.android.com/training/app-links/verify-site-associations#fix-errors), it can cause the system to not verify all Android App Links for that app.
- Starting on Android 12 (API level 31), apps benefit from a [reduced attack surface](https://developer.android.com/training/app-links/deep-linking). A generic web intent resolves to the user's default browser app unless the target app is approved for the specific domain contained in that web intent.

All deep links must be enumerated and verified for correct website association. The actions they perform must be well tested, especially all input data, which should be deemed untrustworthy and thus should always be validated.

### Static Analysis

#### Enumerate Deep Links

**Inspecting the Android Manifest:**

You can easily determine whether deep links (with or without custom URL schemes) are defined by [decoding the app using apktool](0x05b-Basic-Security_Testing.md#exploring-the-app-package) and inspecting the Android Manifest file looking for [`<intent-filter>` elements](https://developer.android.com/guide/components/intents-filters.html#DataTest "intent-filters - DataTest").

- **Custom Url Schemes**: The following example specifies a deep link with a custom URL scheme called `myapp://`.

  ```xml
  <activity android:name=".MyUriActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" android:host="path" />
    </intent-filter>
  </activity>
  ```

- **Deep Links**: The following example specifies a deep Link using both the `http://` and `https://` schemes, along with the host and path that will activate it (in this case, the full URL would be `https://www.myapp.com/my/app/path`):

  ```xml
  <intent-filter>
    ...
    <data android:scheme="http" android:host="www.myapp.com" android:path="/my/app/path" />
    <data android:scheme="https" android:host="www.myapp.com" android:path="/my/app/path" />
  </intent-filter>
  ```

- **App Links**: If the `<intent-filter>` includes the flag `android:autoVerify="true"`, this causes the Android system to reach out to the declared `android:host` in an attempt to access the [Digital Asset Links file](https://developers.google.com/digital-asset-links/v1/getting-started "Digital Asset Link") in order to [verify the App Links](https://developer.android.com/training/app-links/verify-site-associations "Verify Android App Links"). **A deep link can be considered an App Link only if the verification is successful.**

  ```xml
  <intent-filter android:autoVerify="true">
  ```

When listing deep links remember that `<data>` elements within the same `<intent-filter>` are actually merged together to account for all variations of their combined attributes.

```xml
<intent-filter>
  ...
  <data android:scheme="https" android:host="www.example.com" />
  <data android:scheme="app" android:host="open.my.app" />
</intent-filter>
```

It might seem as though this supports only `https://www.example.com` and `app://open.my.app`. However, it actually supports:

- `https://www.example.com`
- `app://open.my.app`
- `app://www.example.com`
- `https://open.my.app`

**Using Dumpsys:**

Use [adb](0x08-Testing-Tools.md#adb) to run the following command that will show all schemes:

```bash
adb shell dumpsys package com.example.package
```

**Using Android "App Link Verification" Tester:**

Use the [Android "App Link Verification" Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester) script to list all deep links (`list-all`) or only app links (`list-applinks`):

```bash
python3 deeplink_analyser.py -op list-all -apk ~/Downloads/example.apk

.MainActivity

app://open.my.app
app://www.example.com
https://open.my.app
https://www.example.com
```

#### Check for Correct Website Association

Even if deep links contain the `android:autoVerify="true"` attribute, they must be _actually_ verified in order to be considered App Links. You should test for any possible misconfigurations that might prevent full verification.

##### Automatic Verification

Use the [Android "App Link Verification" Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester) script to get the verification status for all app links (`verify-applinks`). See an example [here](https://github.com/inesmartins/Android-App-Link-Verification-Tester#use-an-apk-to-check-for-dals-for-all-app-links).

**Only on Android 12 (API level 31) or higher:**

You can use [adb](0x08-Testing-Tools.md#adb) to test the verification logic regardless of whether the app targets Android 12 (API level 31) or not. This feature allows you to:

- [invoke the verification process manually](https://developer.android.com/training/app-links/verify-site-associations#manual-verification).
- [reset the state of the target app's Android App Links on your device](https://developer.android.com/training/app-links/verify-site-associations#reset-state).
- [invoke the domain verification process](https://developer.android.com/training/app-links/verify-site-associations#invoke-domain-verification).

You can also [review the verification results](https://developer.android.com/training/app-links/verify-site-associations#review-results). For example:

```bash
adb shell pm get-app-links com.example.package

com.example.package:
    ID: 01234567-89ab-cdef-0123-456789abcdef
    Signatures: [***]
    Domain verification state:
      example.com: verified
      sub.example.com: legacy_failure
      example.net: verified
      example.org: 1026
```

> The same information can be found by running `adb shell dumpsys package com.example.package` (only on Android 12 (API level 31) or higher).

##### Manual Verification

This section details a few, of potentially many, reasons why the verification process failed or was not actually triggered. See more information in the [Android Developers Documentation](https://developer.android.com/training/app-links/verify-site-associations#fix-errors) and in the white paper ["Measuring the Insecurity of Mobile Deep Links of Android"](https://people.cs.vt.edu/gangwang/deep17.pdf).

**Check the [Digital Asset Links file](https://developers.google.com/digital-asset-links/v1/getting-started "Digital Asset Link"):**

- Check for **missing** Digital Asset Links file:
  - try to find it in the domain's `/.well-known/` path. Example: `https://www.example.com/.well-known/assetlinks.json`
  - or try `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=www.example.com`
- Check for valid Digital Asset Links file **served via HTTP**.
- Check for **invalid** Digital Asset Links files served via HTTPS. For example:
  - the file contains invalid JSON.
  - the file doesn't include the target app's package.

**Check for Redirects:**

To enhance the app security, the system [doesn't verify any Android App Links](https://developer.android.com/training/app-links/verify-site-associations#fix-errors) for an app if the server sets a redirect such as `http://example.com` to `https://example.com` or `example.com` to `www.example.com`.

**Check for Subdomains:**

If an intent filter lists multiple hosts with different subdomains, there must be a valid Digital Asset Links file on each domain. For example, the following intent filter includes `www.example.com` and `mobile.example.com` as accepted intent URL hosts.

```xml
<application>
  <activity android:name=”MainActivity”>
    <intent-filter android:autoVerify="true">
      <action android:name="android.intent.action.VIEW" />
      <category android:name="android.intent.category.DEFAULT" />
      <category android:name="android.intent.category.BROWSABLE" />
      <data android:scheme="https" />
      <data android:scheme="https" />
      <data android:host="www.example.com" />
      <data android:host="mobile.example.com" />
    </intent-filter>
  </activity>
</application>
```

In order for the deep links to correctly register, a valid Digital Asset Links file must be published at both `https://www.example.com/.well-known/assetlinks.json` and `https://mobile.example.com/.well-known/assetlinks.json`.

**Check for Wildcards:**

If the hostname includes a wildcard (such as `*.example.com`), you should be able to find a valid Digital Asset Links file at the root hostname: `https://example.com/.well-known/assetlinks.json`.

#### Check the Handler Method

Even if the deep link is correctly verified, the logic of the handler method should be carefully analyzed. Pay special attention to **deep links being used to transmit data** (which is controlled externally by the user or any other app).

First, obtain the name of the Activity from the Android Manifest `<activity>` element which defines the target `<intent-filter>` and search for usage of [`getIntent`](https://developer.android.com/reference/android/content/Intent#getIntent(java.lang.String) "getIntent()") and [`getData`](https://developer.android.com/reference/android/content/Intent#getData%28%29 "getData()"). This general approach of locating these methods can be used across most applications when performing reverse engineering and is key when trying to understand how the application uses deep links and handles any externally provided input data and if it could be subject to any kind of abuse.

The following example is a snippet from an exemplary Kotlin app [decompiled with jadx](0x05c-Reverse-Engineering-and-Tampering.md#decompiling-java-code). From the [static analysis](#enumerate-deep-links) we know that it supports the deep link `deeplinkdemo://load.html/` as part of `com.mstg.deeplinkdemo.WebViewActivity`.

```java
// snippet edited for simplicity
public final class WebViewActivity extends AppCompatActivity {
    private ActivityWebViewBinding binding;

    public void onCreate(Bundle savedInstanceState) {
        Uri data = getIntent().getData();
        String html = data == null ? null : data.getQueryParameter("html");
        Uri data2 = getIntent().getData();
        String deeplink_url = data2 == null ? null : data2.getQueryParameter("url");
        View findViewById = findViewById(R.id.webView);
        if (findViewById != null) {
            WebView wv = (WebView) findViewById;
            wv.getSettings().setJavaScriptEnabled(true);
            if (deeplink_url != null) {
                wv.loadUrl(deeplink_url);
            ...
```

You can simply follow the `deeplink_url` String variable and see the result from the `wv.loadUrl` call. This means the attacker has full control of the URL being loaded to the WebView (as shown above has [JavaScript enabled](#testing-javascript-execution-in-webviews-mstg-platform-5).

The same WebView might be also rendering an attacker controlled parameter. In that case, the following deep link payload would trigger [Reflected Cross-Site Scripting (XSS)](0x04h-Testing-Code-Quality.md#cross-site-scripting-flaws-mstg-platform-2) within the context of the WebView:

```default
deeplinkdemo://load.html?attacker_controlled=<svg onload=alert(1)>
```

But there are many other possibilities. Be sure to check the following sections to learn more about what to expect and how to test different scenarios:

- ["Cross-Site Scripting Flaws (MSTG-PLATFORM-2)"](0x04h-Testing-Code-Quality.md#cross-site-scripting-flaws-mstg-platform-2).
- ["Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2)"](0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2).
- ["Testing Object Persistence (MSTG-PLATFORM-8)"](#testing-object-persistence-mstg-platform-8).
- ["Testing for URL Loading in WebViews (MSTG-PLATFORM-2)"](#testing-for-url-loading-in-webviews-mstg-platform-2)
- ["Testing JavaScript Execution in WebViews (MSTG-PLATFORM-5)"](#testing-javascript-execution-in-webviews-mstg-platform-5)
- ["Testing WebView Protocol Handlers (MSTG-PLATFORM-6)"](#testing-webview-protocol-handlers-mstg-platform-6)

In addition, we recommend to search and read public reports (search term: `"deep link*"|"deeplink*" site:https://hackerone.com/reports/`). For example:

- ["[HackerOne#1372667] Able to steal bearer token from deep link"](https://hackerone.com/reports/1372667)
- ["[HackerOne#401793] Insecure deeplink leads to sensitive information disclosure"](https://hackerone.com/reports/401793)
- ["[HackerOne#583987] Android app deeplink leads to CSRF in follow action"](https://hackerone.com/reports/583987)
- ["[HackerOne#637194] Bypass of biometrics security functionality is possible in Android application"](https://hackerone.com/reports/637194)
- ["[HackerOne#341908] XSS via Direct Message deeplinks"](https://hackerone.com/reports/341908)

### Dynamic Analysis

Here you will use the list of deep links from the static analysis to iterate and determine each handler method and the processed data, if any. You will first start a [Frida](0x08-Testing-Tools.md#frida) hook and then begin invoking the deep links.

The following example assumes a target app that accepts this deep link: `deeplinkdemo://load.html`. However, we don't know the corresponding handler method yet, nor the parameters it potentially accepts.

**[Step 1] Frida Hooking:**

You can use the script ["Android Deep Link Observer"](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/) from [Frida CodeShare](0x08-Testing-Tools.md#frida-codeshare) to monitor all invoked deep links triggering a call to `Intent.getData`. You can also use the script as a base to include your own modifications depending on the use case at hand. In this case we [included the stack trace](https://github.com/FrenchYeti/frida-trick/blob/master/README.md) in the script since we are interested in the method which calls `Intent.getData`.

**[Step 2] Invoking Deep Links:**

Now you can invoke any of the deep links using [adb](0x08-Testing-Tools.md#adb) and the [Activity Manager (am)](https://developer.android.com/training/app-links/deep-linking#testing-filters "Activity Manager") which will send intents within the Android device. For example:

```bash
adb shell am start -W -a android.intent.action.VIEW -d "deeplinkdemo://load.html/?message=ok#part1"

Starting: Intent { act=android.intent.action.VIEW dat=deeplinkdemo://load.html/?message=ok }
Status: ok
LaunchState: WARM
Activity: com.mstg.deeplinkdemo/.WebViewActivity
TotalTime: 210
WaitTime: 217
Complete
```

> This might trigger the disambiguation dialog when using the "http/https" schema or if other installed apps support the same custom URL schema. You can include the package name to make it an explicit intent.

This invocation will log the following:

```bash
[*] Intent.getData() was called
[*] Activity: com.mstg.deeplinkdemo.WebViewActivity
[*] Action: android.intent.action.VIEW

[*] Data
- Scheme: deeplinkdemo://
- Host: /load.html
- Params: message=ok
- Fragment: part1

[*] Stacktrace:

android.content.Intent.getData(Intent.java)
com.mstg.deeplinkdemo.WebViewActivity.onCreate(WebViewActivity.kt)
android.app.Activity.performCreate(Activity.java)
...
com.android.internal.os.ZygoteInit.main(ZygoteInit.java)
```

In this case we've crafted the deep link including arbitrary parameters (`?message=ok`) and fragment (`#part1`). We still don't know if they are being used. The information above reveals useful information that you can use now to reverse engineer the app. See the section ["Check the Handler Method"](#check-the-handler-method) to learn about things you should consider.

- File: `WebViewActivity.kt`
- Class: `com.mstg.deeplinkdemo.WebViewActivity`
- Method: `onCreate`
  
> Sometimes you can even take advantage of other applications that you know interact with your target app. You can reverse engineer the app, (e.g. to extract all strings and filter those which include the target deep links, `deeplinkdemo:///load.html` in the previous case), or use them as triggers, while hooking the app as previously discussed.

## Testing for Sensitive Functionality Exposure Through IPC (MSTG-PLATFORM-4)

### Overview

During implementation of a mobile application, developers may apply traditional techniques for IPC (such as using shared files or network sockets). The IPC system functionality offered by mobile application platforms should be used because it is much more mature than traditional techniques. Using IPC mechanisms with no security in mind may cause the application to leak or expose sensitive data.

The following is a list of Android IPC Mechanisms that may expose sensitive data:

- [Binders](https://developer.android.com/reference/android/os/Binder.html "IPCBinder")
- [Services](https://developer.android.com/guide/components/services.html "IPCServices")
- [Bound Services](https://developer.android.com/guide/components/bound-services.html "BoundServices")
- [AIDL](https://developer.android.com/guide/components/aidl.html "AIDL")
- [Intents](https://developer.android.com/reference/android/content/Intent.html "IPCIntent")
- [Content Providers](https://developer.android.com/reference/android/content/ContentProvider.html "IPCContentProviders")

### Static Analysis

We start by looking at the AndroidManifest.xml, where all activities, services, and content providers included in the source code must be declared (otherwise the system won't recognize them and they won't run). Broadcast receivers can be declared in the manifest or created dynamically. You will want to identify elements such as

- [`<intent-filter>`](https://developer.android.com/guide/topics/manifest/intent-filter-element.html "IntentFilterElement")
- [`<service>`](https://developer.android.com/guide/topics/manifest/service-element.html "ServiceElement")
- [`<provider>`](https://developer.android.com/guide/topics/manifest/provider-element.html "ProviderElement")
- [`<receiver>`](https://developer.android.com/guide/topics/manifest/receiver-element.html "ReceiverElement")

An "exported" activity, service, or content can be accessed by other apps. There are two common ways to designate a component as exported. The obvious one is setting the export tag to true `android:exported="true"`. The second way involves defining an `<intent-filter>` within the component element (`<activity>`, `<service>`, `<receiver>`). When this is done, the export tag is automatically set to "true". To prevent all other Android apps from interacting with the IPC component element, be sure that the `android:exported="true"` value and an `<intent-filter>` aren't in their `AndroidManifest.xml` files unless this is necessary.

Remember that using the permission tag (`android:permission`) will also limit other applications' access to a component. If your IPC is intended to be accessible to other applications, you can apply a security policy with the `<permission>` element and set a proper `android:protectionLevel`. When `android:permission` is used in a service declaration, other applications must declare a corresponding `<uses-permission>` element in their own manifest to start, stop, or bind to the service.

For more information about the content providers, please refer to the test case "Testing Whether Stored Sensitive Data Is Exposed via IPC Mechanisms" in chapter "Testing Data Storage".

Once you identify a list of IPC mechanisms, review the source code to see whether sensitive data is leaked when the mechanisms are used. For example, content providers can be used to access database information, and services can be probed to see if they return data. Broadcast receivers can leak sensitive information if probed or sniffed.

In the following, we use two example apps and give examples of identifying vulnerable IPC components:

- ["Sieve"](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk "Sieve: Vulnerable Password Manager")
- ["Android Insecure Bank"](https://github.com/dineshshetty/Android-InsecureBankv2 "Android Insecure Bank V2")

### Activities

#### Inspect the AndroidManifest

In the "Sieve" app, we find three exported activities, identified by `<activity>`:

```xml
<activity android:excludeFromRecents="true" android:label="@string/app_name" android:launchMode="singleTask" android:name=".MainLoginActivity" android:windowSoftInputMode="adjustResize|stateVisible">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:finishOnTaskLaunch="true" android:label="@string/title_activity_file_select" android:name=".FileSelectActivity" />
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:finishOnTaskLaunch="true" android:label="@string/title_activity_pwlist" android:name=".PWList" />

```

#### Inspect the Source Code

By inspecting the `PWList.java` activity, we see that it offers options to list all keys, add, delete, etc. If we invoke it directly, we will be able to bypass the LoginActivity. More on this can be found in the dynamic analysis below.

### Services

#### Inspect the AndroidManifest

In the "Sieve" app, we find two exported services, identified by `<service>`:

```xml
<service android:exported="true" android:name=".AuthService" android:process=":remote" />
<service android:exported="true" android:name=".CryptoService" android:process=":remote" />
```

#### Inspect the Source Code

Check the source code for the class `android.app.Service`:

By reversing the target application, we can see that the service `AuthService` provides functionality for changing the password and PIN-protecting the target app.

```java
   public void handleMessage(Message msg) {
            AuthService.this.responseHandler = msg.replyTo;
            Bundle returnBundle = msg.obj;
            int responseCode;
            int returnVal;
            switch (msg.what) {
                ...
                case AuthService.MSG_SET /*6345*/:
                    if (msg.arg1 == AuthService.TYPE_KEY) /*7452*/ {
                        responseCode = 42;
                        if (AuthService.this.setKey(returnBundle.getString("com.mwr.example.sieve.PASSWORD"))) {
                            returnVal = 0;
                        } else {
                            returnVal = 1;
                        }
                    } else if (msg.arg1 == AuthService.TYPE_PIN) {
                        responseCode = 41;
                        if (AuthService.this.setPin(returnBundle.getString("com.mwr.example.sieve.PIN"))) {
                            returnVal = 0;
                        } else {
                            returnVal = 1;
                        }
                    } else {
                        sendUnrecognisedMessage();
                        return;
                    }
           }
   }
```

### Broadcast Receivers

#### Inspect the AndroidManifest

In the "Android Insecure Bank" app, we find a broadcast receiver in the manifest, identified by `<receiver>`:

```xml
<receiver android:exported="true" android:name="com.android.insecurebankv2.MyBroadCastReceiver">
    <intent-filter>
        <action android:name="theBroadcast" />
    </intent-filter>
</receiver>
```

#### Inspect the Source Code

Search the source code for strings like `sendBroadcast`, `sendOrderedBroadcast`, and `sendStickyBroadcast`. Make sure that the application doesn't send any sensitive data.

If an Intent is broadcasted and received within the application only, `LocalBroadcastManager` can be used to prevent other apps from receiving the broadcast message. This reduces the risk of leaking sensitive information.

To understand more about what the receiver is intended to do, we have to go deeper in our static analysis and search for usage of the class `android.content.BroadcastReceiver` and the `Context.registerReceiver` method, which is used to dynamically create receivers.

The following extract of the target application's source code shows that the broadcast receiver triggers transmission of an SMS message containing the user's decrypted password.

```java
public class MyBroadCastReceiver extends BroadcastReceiver {
  String usernameBase64ByteString;
  public static final String MYPREFS = "mySharedPreferences";

  @Override
  public void onReceive(Context context, Intent intent) {
    // TODO Auto-generated method stub

        String phn = intent.getStringExtra("phonenumber");
        String newpass = intent.getStringExtra("newpass");

    if (phn != null) {
      try {
                SharedPreferences settings = context.getSharedPreferences(MYPREFS, Context.MODE_WORLD_READABLE);
                final String username = settings.getString("EncryptedUsername", null);
                byte[] usernameBase64Byte = Base64.decode(username, Base64.DEFAULT);
                usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
                final String password = settings.getString("superSecurePassword", null);
                CryptoClass crypt = new CryptoClass();
                String decryptedPassword = crypt.aesDeccryptedString(password);
                String textPhoneno = phn.toString();
                String textMessage = "Updated Password from: "+decryptedPassword+" to: "+newpass;
                SmsManager smsManager = SmsManager.getDefault();
                System.out.println("For the changepassword - phonenumber: "+textPhoneno+" password is: "+textMessage);
smsManager.sendTextMessage(textPhoneno, null, textMessage, null, null);
          }
     }
  }
}
```

BroadcastReceivers should use the `android:permission` attribute;  otherwise, other applications can invoke them. You can use `Context.sendBroadcast(intent, receiverPermission);` to specify permissions a receiver must have to [read the broadcast](https://developer.android.com/reference/android/content/Context#sendBroadcast%28android.content.Intent,%20java.lang.String%29 "SendBroadcast"). You can also set an explicit application package name that limits the components this Intent will resolve to. If left as the default value (null), all components in all applications will be considered. If non-null, the Intent can match only the components in the given application package.

### Dynamic Analysis

You can enumerate IPC components with [MobSF](0x08-Testing-Tools.md#mobsf "MobSF"). To list all exported IPC components, upload the APK file and the components collection will be displayed in the following screen:

<img src="Images/Chapters/0x05h/MobSF_Show_Components.png" width="100%" />

#### Content Providers

The "Sieve" application implements a vulnerable content provider. To list the content providers exported by the Sieve app, execute the following command:

```bash
$ adb shell dumpsys package com.mwr.example.sieve | grep -Po "Provider{[\w\d\s\./]+}" | sort -u
Provider{34a20d5 com.mwr.example.sieve/.FileBackupProvider}
Provider{64f10ea com.mwr.example.sieve/.DBContentProvider}
```

Once identified, you can use [jadx](0x08-Testing-Tools.md#jadx "jadx") to reverse engineer the app and analyze the source code of the exported content providers to identify potential vulnerabilities.

To identify the corresponding class of a content provider, use the following information:

- Package Name: `com.mwr.example.sieve`.
- Content Provider Class Name: `DBContentProvider`.

When analyzing the class `com.mwr.example.sieve.DBContentProvider`, you'll see that it contains several URIs:

```java
package com.mwr.example.sieve;
...
public class DBContentProvider extends ContentProvider {
    public static final Uri KEYS_URI = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Keys");
    public static final Uri PASSWORDS_URI = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Passwords");
...
}
```

Use the following commands to call the content provider using the identified URIs:

```bash
$ adb shell content query --uri content://com.mwr.example.sieve.DBContentProvider/Keys/
Row: 0 Password=1234567890AZERTYUIOPazertyuiop, pin=1234

$ adb shell content query --uri content://com.mwr.example.sieve.DBContentProvider/Passwords/
Row: 0 _id=1, service=test, username=test, password=BLOB, email=t@tedt.com
Row: 1 _id=2, service=bank, username=owasp, password=BLOB, email=user@tedt.com

$ adb shell content query --uri content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection email:username:password --where 'service=\"bank\"'
Row: 0 email=user@tedt.com, username=owasp, password=BLOB
```

You are able now to retrieve all database entries (see all lines starting with "Row:" in the output).

#### Activities

To list activities exported by an application, you can use the following command and focus on `activity` elements:

```bash
$ aapt d xmltree sieve.apk AndroidManifest.xml
...
E: activity (line=32)
  A: android:label(0x01010001)=@0x7f05000f
  A: android:name(0x01010003)=".FileSelectActivity" (Raw: ".FileSelectActivity")
  A: android:exported(0x01010010)=(type 0x12)0xffffffff
  A: android:finishOnTaskLaunch(0x01010014)=(type 0x12)0xffffffff
  A: android:clearTaskOnLaunch(0x01010015)=(type 0x12)0xffffffff
  A: android:excludeFromRecents(0x01010017)=(type 0x12)0xffffffff
E: activity (line=40)
  A: android:label(0x01010001)=@0x7f050000
  A: android:name(0x01010003)=".MainLoginActivity" (Raw: ".MainLoginActivity")
  A: android:excludeFromRecents(0x01010017)=(type 0x12)0xffffffff
  A: android:launchMode(0x0101001d)=(type 0x10)0x2
  A: android:windowSoftInputMode(0x0101022b)=(type 0x11)0x14
  E: intent-filter (line=46)
    E: action (line=47)
      A: android:name(0x01010003)="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")
    E: category (line=49)
      A: android:name(0x01010003)="android.intent.category.LAUNCHER" (Raw: "android.intent.category.LAUNCHER")
E: activity (line=52)
  A: android:label(0x01010001)=@0x7f050009
  A: android:name(0x01010003)=".PWList" (Raw: ".PWList")
  A: android:exported(0x01010010)=(type 0x12)0xffffffff
  A: android:finishOnTaskLaunch(0x01010014)=(type 0x12)0xffffffff
  A: android:clearTaskOnLaunch(0x01010015)=(type 0x12)0xffffffff
  A: android:excludeFromRecents(0x01010017)=(type 0x12)0xffffffff
E: activity (line=60)
  A: android:label(0x01010001)=@0x7f05000a
  A: android:name(0x01010003)=".SettingsActivity" (Raw: ".SettingsActivity")
  A: android:finishOnTaskLaunch(0x01010014)=(type 0x12)0xffffffff
  A: android:clearTaskOnLaunch(0x01010015)=(type 0x12)0xffffffff
  A: android:excludeFromRecents(0x01010017)=(type 0x12)0xffffffff
...
```

You can identify an exported activity using one of the following properties:

- It have an `intent-filter` sub declaration.
- It have the attribute `android:exported` to `0xffffffff`.

You can also use [jadx](0x08-Testing-Tools.md#jadx "jadx") to identify exported activities in the file `AndroidManifest.xml` using the criteria described above:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.mwr.example.sieve">
...
  <!-- This activity is exported via the attribute "exported" -->
  <activity android:name=".FileSelectActivity" android:exported="true" />
   <!-- This activity is exported via the "intent-filter" declaration  -->
  <activity android:name=".MainLoginActivity">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity>
  <!-- This activity is exported via the attribute "exported" -->
  <activity android:name=".PWList" android:exported="true" />
  <!-- Activities below are not exported -->
  <activity android:name=".SettingsActivity" />
  <activity android:name=".AddEntryActivity"/>
  <activity android:name=".ShortLoginActivity" />
  <activity android:name=".WelcomeActivity" />
  <activity android:name=".PINActivity" />
...
</manifest>
```

Enumerating activities in the vulnerable password manager "Sieve" shows that the following activities are exported:

- `.MainLoginActivity`
- `.PWList`
- `.FileSelectActivity`

Use the command below to launch an activity:

```bash
# Start the activity without specifying an action or an category
$ adb shell am start -n com.mwr.example.sieve/.PWList
Starting: Intent { cmp=com.mwr.example.sieve/.PWList }

# Start the activity indicating an action (-a) and an category (-c)
$ adb shell am start -n "com.mwr.example.sieve/.MainLoginActivity" -a android.intent.action.MAIN -c android.intent.category.LAUNCHER
Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.mwr.example.sieve/.MainLoginActivity }
```

Since the activity `.PWList` is called directly in this example, you can use it to bypass the login form protecting the password manager, and access the data contained within the password manager.

#### Services

Services can be enumerated with the Drozer module `app.service.info`:

```bash
dz> run app.service.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.AuthService
    Permission: null
  com.mwr.example.sieve.CryptoService
    Permission: null
```

To communicate with a service, you must first use static analysis to identify the required inputs.

Because this service is exported, you can use the module `app.service.send` to communicate with the service and change the password stored in the target application:

```bash
dz> run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg 6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj
Got a reply from com.mwr.example.sieve/com.mwr.example.sieve.AuthService:
  what: 4
  arg1: 42
  arg2: 0
  Empty
```

#### Broadcast Receivers

To list broadcast receivers exported by an application, you can use the following command and focus on `receiver` elements:

```bash
$ aapt d xmltree InsecureBankv2.apk AndroidManifest.xml
...
E: receiver (line=88)
  A: android:name(0x01010003)="com.android.insecurebankv2.MyBroadCastReceiver" (Raw: "com.android.insecurebankv2.MyBroadCastReceiver")
  A: android:exported(0x01010010)=(type 0x12)0xffffffff
  E: intent-filter (line=91)
    E: action (line=92)
      A: android:name(0x01010003)="theBroadcast" (Raw: "theBroadcast")
E: receiver (line=119)
  A: android:name(0x01010003)="com.google.android.gms.wallet.EnableWalletOptimizationReceiver" (Raw: "com.google.android.gms.wallet.EnableWalletOptimizationReceiver")
  A: android:exported(0x01010010)=(type 0x12)0x0
  E: intent-filter (line=122)
    E: action (line=123)
      A: android:name(0x01010003)="com.google.android.gms.wallet.ENABLE_WALLET_OPTIMIZATION" (Raw: "com.google.android.gms.wallet.ENABLE_WALLET_OPTIMIZATION")
...
```

You can identify an exported broadcast receiver using one of the following properties:

- It has an `intent-filter` sub declaration.
- It has the attribute `android:exported` set to `0xffffffff`.

You can also use [jadx](0x08-Testing-Tools.md#jadx "jadx") to identify exported broadcast receivers in the file `AndroidManifest.xml` using the criteria described above:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.insecurebankv2">
...
  <!-- This broadcast receiver is exported via the attribute "exported" as well as the "intent-filter" declaration -->
  <receiver android:name="com.android.insecurebankv2.MyBroadCastReceiver" android:exported="true">
    <intent-filter>
      <action android:name="theBroadcast"/>
    </intent-filter>
  </receiver>
  <!-- This broadcast receiver is NOT exported because the attribute "exported" is explicitly set to false -->
  <receiver android:name="com.google.android.gms.wallet.EnableWalletOptimizationReceiver" android:exported="false">
    <intent-filter>
      <action android:name="com.google.android.gms.wallet.ENABLE_WALLET_OPTIMIZATION"/>
    </intent-filter>
  </receiver>
...
</manifest>
```

The above example from the vulnerable banking application [InsecureBankv2](0x08-Testing-Tools.md#android "Vulnerable applications for Android") shows that only the broadcast receiver named `com.android.insecurebankv2.MyBroadCastReceiver` is exported.

Now that you know that there is an exported broadcast receiver, you can dive deeper and reverse engineer the app using [jadx](0x08-Testing-Tools.md#jadx "jadx"). This will allow you to analyze the source code searching for potential vulnerabilities that you could later try to exploit. The source code of the exported broadcast receiver is the following:

```java
package com.android.insecurebankv2;
...
public class MyBroadCastReceiver extends BroadcastReceiver {
    public static final String MYPREFS = "mySharedPreferences";
    String usernameBase64ByteString;

    public void onReceive(Context context, Intent intent) {
        String phn = intent.getStringExtra("phonenumber");
        String newpass = intent.getStringExtra("newpass");
        if (phn != null) {
            try {
                SharedPreferences settings = context.getSharedPreferences("mySharedPreferences", 1);
                this.usernameBase64ByteString = new String(Base64.decode(settings.getString("EncryptedUsername", (String) null), 0), "UTF-8");
                String decryptedPassword = new CryptoClass().aesDeccryptedString(settings.getString("superSecurePassword", (String) null));
                String textPhoneno = phn.toString();
                String textMessage = "Updated Password from: " + decryptedPassword + " to: " + newpass;
                SmsManager smsManager = SmsManager.getDefault();
                System.out.println("For the changepassword - phonenumber: " + textPhoneno + " password is: " + textMessage);
                smsManager.sendTextMessage(textPhoneno, (String) null, textMessage, (PendingIntent) null, (PendingIntent) null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Phone number is null");
        }
    }
}
```

As you can see in the source code, this broadcast receiver expects two parameters named `phonenumber` and `newpass`. With this information you can now try to exploit this broadcast receiver by sending events to it using custom values:

```bash
# Send an event with the following properties:
# Action is set to "theBroadcast"
# Parameter "phonenumber" is set to the string "07123456789"
# Parameter "newpass" is set to the string "12345"
$ adb shell am broadcast -a theBroadcast --es phonenumber "07123456789" --es newpass "12345"
Broadcasting: Intent { act=theBroadcast flg=0x400000 (has extras) }
Broadcast completed: result=0
```

This generates the following SMS:

```bash
Updated Password from: SecretPassword@ to: 12345
```

##### Sniffing Intents

If an Android application broadcasts intents without setting a required permission or specifying the destination package, the intents can be monitored by any application that runs on the device.

To register a broadcast receiver to sniff intents, use the Drozer module `app.broadcast.sniff` and specify the action to monitor with the `--action` parameter:

```bash
dz> run app.broadcast.sniff  --action theBroadcast
[*] Broadcast receiver registered to sniff matching intents
[*] Output is updated once a second. Press Control+C to exit.

Action: theBroadcast
Raw: Intent { act=theBroadcast flg=0x10 (has extras) }
Extra: phonenumber=07123456789 (java.lang.String)
Extra: newpass=12345 (java.lang.String)`
```

You can also use the following command to sniff the intents. However, the content of the extras passed will not be displayed:

```bash
$ adb shell dumpsys activity broadcasts | grep "theBroadcast"
BroadcastRecord{fc2f46f u0 theBroadcast} to user 0
Intent { act=theBroadcast flg=0x400010 (has extras) }
BroadcastRecord{7d4f24d u0 theBroadcast} to user 0
Intent { act=theBroadcast flg=0x400010 (has extras) }
45: act=theBroadcast flg=0x400010 (has extras)
46: act=theBroadcast flg=0x400010 (has extras)
121: act=theBroadcast flg=0x400010 (has extras)
144: act=theBroadcast flg=0x400010 (has extras)
```

## Testing JavaScript Execution in WebViews (MSTG-PLATFORM-5)

### Overview

JavaScript can be injected into web applications via reflected, stored, or DOM-based Cross-Site Scripting (XSS). Mobile apps are executed in a sandboxed environment and don't have this vulnerability when implemented natively. Nevertheless, WebViews may be part of a native app to allow web page viewing. Every app has its own WebView cache, which isn't shared with the native Browser or other apps. On Android, WebViews use the WebKit rendering engine to display web pages, but the pages are stripped down to minimal functions, for example, pages don't have address bars. If the WebView implementation is too lax and allows usage of JavaScript, JavaScript can be used to attack the app and gain access to its data.

### Static Analysis

The source code must be checked for usage and implementations of the WebView class. To create and use a WebView, you must create an instance of the WebView class.

```java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("https://www.owasp.org/");
```

Various settings can be applied to the WebView (activating/deactivating JavaScript is one example). JavaScript is disabled by default for WebViews and must be explicitly enabled. Look for the method [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled%28boolean%29 "setJavaScriptEnabled in WebViews") to check for JavaScript activation.

```java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript. It should be enabled only if necessary to reduce the attack surface to the app. If JavaScript is necessary, you should make sure that

- The communication to the endpoints consistently relies on HTTPS (or other protocols that allow encryption) to protect HTML and JavaScript from tampering during transmission.
- JavaScript and HTML are loaded locally, from within the app data directory or from trusted web servers only.
- The user cannot define which sources to load by means of loading different resources based on a user provided input.

To remove all JavaScript source code and locally stored data, clear the WebView's cache with [`clearCache`](https://developer.android.com/reference/android/webkit/WebView#clearCache%28boolean%29 "clearCache in WebViews") when the app closes.

Devices running platforms older than Android 4.4 (API level 19) use a version of WebKit that has several security issues. As a workaround, the app must confirm that WebView objects [display only trusted content](https://developer.android.com/training/articles/security-tips.html#WebView "WebView Best Practices") if the app runs on these devices.

### Dynamic Analysis

Dynamic Analysis depends on operating conditions. There are several ways to inject JavaScript into an app's WebView:

- Stored Cross-Site Scripting vulnerabilities in an endpoint; the exploit will be sent to the mobile app's WebView when the user navigates to the vulnerable function.
- Attacker takes a man-in-the-middle (MITM) position and tampers with the response by injecting JavaScript.
- Malware tampering with local files that are loaded by the WebView.

To address these attack vectors, check the following:

- All functions offered by the endpoint should be free of [stored XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting "Stored Cross-Site Scripting").
- Only files that are in the app data directory should be rendered in a WebView (see test case "Testing for Local File Inclusion in WebViews").

- The HTTPS communication must be implemented according to best practices to avoid MITM attacks. This means:
  - all communication is encrypted via TLS (see test case "Testing for Unencrypted Sensitive Data on the Network"),
  - the certificate is checked properly (see test case "Testing Endpoint Identify Verification"), and/or
  - the certificate should be pinned (see "Testing Custom Certificate Stores and Certificate Pinning").

## Testing WebView Protocol Handlers (MSTG-PLATFORM-6)

### Overview

Several default [schemas](https://developer.android.com/guide/appendix/g-app-intents.html "Intent List") are available for Android URLs. They can be triggered within a WebView with the following:

- http(s)://
- file://
- tel://

WebViews can load remote content from an endpoint, but they can also load local content from the app data directory or external storage. If the local content is loaded, the user shouldn't be able to influence the filename or the path used to load the file, and users shouldn't be able to edit the loaded file.

### Static Analysis

Check the source code for WebView usage. The following [WebView settings](https://developer.android.com/reference/android/webkit/WebSettings.html "WebView Settings") control resource access:

- `setAllowContentAccess`: Content URL access allows WebViews to load content from a content provider installed on the system, which is enabled by default .
- `setAllowFileAccess`: Enables and disables file access within a WebView. The default value is `true` when targeting Android 10 (API level 29) and below and `false` for Android 11 (API level 30) and above. Note that this enables and disables [file system access](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29 "File Access in WebView") only. Asset and resource access is unaffected and accessible via `file:///android_asset` and `file:///android_res`.
- `setAllowFileAccessFromFileURLs`: Does or does not allow JavaScript running in the context of a file scheme URL to access content from other file scheme URLs. The default value is `true` for Android 4.0.3 - 4.0.4 (API level 15) and below and `false` for Android 4.1 (API level 16) and above.
- `setAllowUniversalAccessFromFileURLs`: Does or does not allow JavaScript running in the context of a file scheme URL to access content from any origin. The default value is `true` for Android 4.0.3 - 4.0.4 (API level 15) and below and `false` for Android 4.1 (API level 16) and above.

If one or more of the above methods is/are activated, you should determine whether the method(s) is/are really necessary for the app to work properly.

If a WebView instance can be identified, find out whether local files are loaded with the [`loadURL`](https://developer.android.com/reference/android/webkit/WebView.html#loadUrl%28java.lang.String%29 "loadURL in WebView") method.

```java
WebView = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

The location from which the HTML file is loaded must be verified. If the file is loaded from external storage, for example, the file is readable and writable by everyone. This is considered a bad practice. Instead, the file should be placed in the app's assets directory.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in `loadURL` should be checked for dynamic parameters that can be manipulated; their manipulation may lead to local file inclusion.

Use the following [code snippet and best practices](https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation "WebView best practices") to deactivate protocol handlers, if applicable:

```java
//If attackers can inject script into a WebView, they could access local resources. This can be prevented by disabling local file system access, which is enabled by default. You can use the Android WebSettings class to disable local file system access via the public method `setAllowFileAccess`.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

- Create a list that defines local and remote web pages and protocols that are allowed to be loaded.
- Create checksums of the local HTML/JavaScript files and check them while the app is starting up. Minify JavaScript files to make them harder to read.

### Dynamic Analysis

To identify the usage of protocol handlers, look for ways to trigger phone calls and ways to access files from the file system while you're using the app.

## Determining Whether Java Objects Are Exposed Through WebViews (MSTG-PLATFORM-7)

### Overview

Android offers a way for JavaScript executed in a WebView to call and use native functions of an Android app (annotated with `@JavascriptInterface`) by using the [`addJavascriptInterface`](https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface%28java.lang.Object,%20java.lang.String%29 "Method addJavascriptInterface()") method. This is known as a _WebView JavaScript bridge_ or _native bridge_.

Please note that **when you use `addJavascriptInterface`, you're explicitly granting access to the registered JavaScript Interface object to all pages loaded within that WebView**. This implies that, if the user navigates outside your app or domain, all other external pages will also have access to those JavaScript Interface objects which might present a potential security risk if any sensitive data is being exposed though those interfaces.

> Warning: Take extreme care with apps targeting Android versions below Android 4.2 (API level 17) as they are [vulnerable to a flaw](https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/ "WebView addJavascriptInterface Remote Code Execution") in the implementation of `addJavascriptInterface`: an attack that is abusing reflection, which leads to remote code execution when malicious JavaScript is injected into a WebView. This was due to all Java Object methods being accessible by default (instead of only those annotated).

### Static Analysis

You need to determine whether the method `addJavascriptInterface` is used, how it is used, and whether an attacker can inject malicious JavaScript.

The following example shows how `addJavascriptInterface` is used to bridge a Java Object and JavaScript in a WebView:

```java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android 4.2 (API level 17) and above, an annotation `@JavascriptInterface` explicitly allows JavaScript to access a Java method.

```java
public class MSTG_ENV_008_JS_Interface {

        Context mContext;

        /** Instantiate the interface and set the context */
        MSTG_ENV_005_JS_Interface(Context c) {
            mContext = c;
        }

        @JavascriptInterface
        public String returnString () {
            return "Secret String";
        }

        /** Show a toast from the web page */
        @JavascriptInterface
        public void showToast(String toast) {
            Toast.makeText(mContext, toast, Toast.LENGTH_SHORT).show();
        }
}
```

This is how you can call the method `returnString` from JavaScript, the string "Secret String" will be stored in the variable `result`:

```javascript
var result = window.Android.returnString();
```

With access to the JavaScript code, via, for example, stored XSS or a MITM attack, an attacker can directly call the exposed Java methods.

If `addJavascriptInterface` is necessary, take the following considerations:

- Only JavaScript provided with the APK should be allowed to use the bridges, e.g. by verifying the URL on each bridged Java method (via `WebView.getUrl`).
- No JavaScript should be loaded from remote endpoints, e.g. by keeping page navigation within the app's domains and opening all other domains on the default browser (e.g. Chrome, Firefox).
- If necessary for legacy reasons (e.g. having to support older devices), at least set the minimal API level to 17 in the manifest file of the app (`<uses-sdk android:minSdkVersion="17" />`).

### Dynamic Analysis

Dynamic analysis of the app can show you which HTML or JavaScript files are loaded and which vulnerabilities are present. The procedure for exploiting the vulnerability starts with producing a JavaScript payload and injecting it into the file that the app is requesting. The injection can be accomplished via a MITM attack or direct modification of the file if it is stored in external storage. The whole process can be accomplished via Drozer and weasel (MWR's advanced exploitation payload), which can install a full agent, injecting a limited agent into a running process or connecting a reverse shell as a Remote Access Tool (RAT).

A full description of the attack is included in the [blog article by MWR](https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/ "WebView addJavascriptInterface Remote Code Execution").

## Testing Object Persistence (MSTG-PLATFORM-8)

### Overview

There are several ways to persist an object on Android:

#### Object Serialization

An object and its data can be represented as a sequence of bytes. This is done in Java via [object serialization](https://developer.android.com/reference/java/io/Serializable.html "Serializable"). Serialization is not inherently secure. It is just a binary format (or representation) for locally storing data in a .ser file. Encrypting and signing HMAC-serialized data is possible as long as the keys are stored safely. Deserializing an object requires a class of the same version as the class used to serialize the object. After classes have been changed, the `ObjectInputStream` can't create objects from older .ser files. The example below shows how to create a `Serializable` class by implementing the `Serializable` interface.

```java
import java.io.Serializable;

public class Person implements Serializable {
  private String firstName;
  private String lastName;

  public Person(String firstName, String lastName) {
    this.firstName = firstName;
    this.lastName = lastName;
    }
  //..
  //getters, setters, etc
  //..

}

```

Now you can read/write the object with `ObjectInputStream`/`ObjectOutputStream` in another class.

#### JSON

There are several ways to serialize the contents of an object to JSON. Android comes with the `JSONObject` and `JSONArray` classes. A wide variety of libraries, including [GSON](https://github.com/google/gson "Google Gson"), [Jackson](https://github.com/FasterXML/jackson-core "Jackson core"), [Moshi](https://github.com/square/moshi "Moshi"), can also be used. The main differences between the libraries are whether they use reflection to compose the object, whether they support annotations, whether the create immutable objects, and the amount of memory they use. Note that almost all the JSON representations are String-based and therefore immutable. This means that any secret stored in JSON will be harder to remove from memory.
JSON itself can be stored anywhere, e.g., a (NoSQL) database or a file. You just need to make sure that any JSON that contains secrets has been appropriately protected (e.g., encrypted/HMACed). See the chapter "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" for more details. A simple example (from the GSON User Guide) of writing and reading JSON with GSON follows. In this example, the contents of an instance of the `BagOfPrimitives` is serialized into JSON:

```java
class BagOfPrimitives {
  private int value1 = 1;
  private String value2 = "abc";
  private transient int value3 = 3;
  BagOfPrimitives() {
    // no-args constructor
  }
}

// Serialization
BagOfPrimitives obj = new BagOfPrimitives();
Gson gson = new Gson();
String json = gson.toJson(obj);  

// ==> json is {"value1":1,"value2":"abc"}

```

#### XML

There are several ways to serialize the contents of an object to XML and back. Android comes with the `XmlPullParser` interface which allows for easily maintainable XML parsing. There are two implementations within Android: `KXmlParser` and `ExpatPullParser`. The [Android Developer Guide](https://developer.android.com/training/basics/network-ops/xml#java "Instantiate the parser") provides a great write-up on how to use them. Next, there are various alternatives, such as a `SAX` parser that comes with the Java runtime. For more information, see [a blogpost from ibm.com](https://www.ibm.com/developerworks/opensource/library/x-android/index.html "Working with XML on Android on IBM Developer").
Similarly to JSON, XML has the issue of working mostly String based, which means that String-type secrets will be harder to remove from memory. XML data can be stored anywhere (database, files), but do need additional protection in case of secrets or information that should not be changed. See the chapter "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" for more details. As stated earlier: the true danger in XML lies in the [XML eXternal Entity (XXE)](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing "XML eXternal Entity attack (XXE)") attack as it might allow for reading external data sources that are still accessible within the application.

#### ORM

There are libraries that provide functionality for directly storing the contents of an object in a database and then instantiating the object with the database contents. This is called Object-Relational Mapping (ORM). Libraries that use the SQLite database include

- [OrmLite](http://ormlite.com/ "OrmLite"),
- [SugarORM](https://satyan.github.io/sugar/ "Sugar ORM"),
- [GreenDAO](https://greenrobot.org/greendao/ "GreenDAO") and
- [ActiveAndroid](http://www.activeandroid.com/ "ActiveAndroid").

[Realm](https://realm.io/docs/java/latest/ "Realm Java"), on the other hand, uses its own database to store the contents of a class. The amount of protection that ORM can provide depends primarily on whether the database is encrypted. See the chapter "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" for more details. The Realm website includes a nice [example of ORM Lite](https://github.com/j256/ormlite-examples/tree/master/android/HelloAndroid "OrmLite example").

#### Parcelable

[`Parcelable`](https://developer.android.com/reference/android/os/Parcelable.html "Parcelable") is an interface for classes whose instances can be written to and restored from a [`Parcel`](https://developer.android.com/reference/android/os/Parcel.html "Parcel"). Parcels are often used to pack a class as part of a `Bundle` for an `Intent`. Here's an Android developer documentation example that implements `Parcelable`:

```java
public class MyParcelable implements Parcelable {
     private int mData;

     public int describeContents() {
         return 0;
     }

     public void writeToParcel(Parcel out, int flags) {
         out.writeInt(mData);
     }

     public static final Parcelable.Creator<MyParcelable> CREATOR
             = new Parcelable.Creator<MyParcelable>() {
         public MyParcelable createFromParcel(Parcel in) {
             return new MyParcelable(in);
         }

         public MyParcelable[] newArray(int size) {
             return new MyParcelable[size];
         }
     };

     private MyParcelable(Parcel in) {
         mData = in.readInt();
     }
 }
```

Because this mechanism that involves Parcels and Intents may change over time, and the `Parcelable` may contain `IBinder` pointers, storing data to disk via `Parcelable` is not recommended.

#### Protocol Buffers

[Protocol Buffers](https://developers.google.com/protocol-buffers/ "Google Documentation") by Google, are a platform- and language neutral mechanism for serializing structured data by means of the [Binary Data Format](https://developers.google.com/protocol-buffers/docs/encoding "Encoding").
There have been a few vulnerabilities with Protocol Buffers, such as [CVE-2015-5237](https://www.cvedetails.com/cve/CVE-2015-5237/ "CVE-2015-5237").
Note that Protocol Buffers do not provide any protection for confidentiality: there is no built in encryption.

### Static Analysis

If object persistence is used for storing sensitive information on the device, first make sure that the information is encrypted and signed/HMACed. See the chapters "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" and "[Android Cryptographic APIs](0x05e-Testing-Cryptography.md)" for more details. Next, make sure that the decryption and verification keys are obtainable only after the user has been authenticated. Security checks should be carried out at the correct positions, as defined in [best practices](https://wiki.sei.cmu.edu/confluence/display/java/SER04-J.%20Do%20not%20allow%20serialization%20and%20deserialization%20to%20bypass%20the%20security%20manager "SER04-J. Do not allow serialization and deserialization to bypass the security manager").

There are a few generic remediation steps that you can always take:

1. Make sure that sensitive data has been encrypted and HMACed/signed after serialization/persistence. Evaluate the signature or HMAC before you use the data. See the chapter "[Android Cryptographic APIs](0x05e-Testing-Cryptography.md)" for more details.
2. Make sure that the keys used in step 1 can't be extracted easily. The user and/or application instance should be properly authenticated/authorized to obtain the keys. See the chapter "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" for more details.
3. Make sure that the data within the de-serialized object is carefully validated before it is actively used (e.g., no exploit of business/application logic).

For high-risk applications that focus on availability, we recommend that you use `Serializable` only when the serialized classes are stable. Second, we recommend not using reflection-based persistence because

- the attacker could find the method's signature via the String-based argument
- the attacker might be able to manipulate the reflection-based steps to execute business logic.

See the chapter "[Android Anti-Reversing Defenses](0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)" for more details.

#### Object Serialization

Search the source code for the following keywords:

- `import java.io.Serializable`
- `implements Serializable`

#### JSON

If you need to counter memory-dumping, make sure that very sensitive information is not stored in the JSON format because you can't guarantee prevention of anti-memory dumping techniques with the standard libraries. You can check for the following keywords in the corresponding libraries:

**`JSONObject`** Search the source code for the following keywords:

- `import org.json.JSONObject;`
- `import org.json.JSONArray;`

**`GSON`** Search the source code for the following keywords:

- `import com.google.gson`
- `import com.google.gson.annotations`
- `import com.google.gson.reflect`
- `import com.google.gson.stream`
- `new Gson();`
- Annotations such as `@Expose`, `@JsonAdapter`, `@SerializedName`,`@Since`, and `@Until`

**`Jackson`** Search the source code for the following keywords:

- `import com.fasterxml.jackson.core`
- `import org.codehaus.jackson` for the older version.

#### ORM

When you use an ORM library, make sure that the data is stored in an encrypted database and the class representations are individually encrypted before storing it. See the chapters "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" and "[Android Cryptographic APIs](0x05e-Testing-Cryptography.md)" for more details. You can check for the following keywords in the corresponding libraries:

**`OrmLite`** Search the source code for the following keywords:

- `import com.j256.*`
- `import com.j256.dao`
- `import com.j256.db`
- `import com.j256.stmt`
- `import com.j256.table\`

Please make sure that logging is disabled.

**`SugarORM`** Search the source code for the following keywords:

- `import com.github.satyan`
- `extends SugarRecord<Type>`
- In the AndroidManifest, there will be `meta-data` entries with values such as `DATABASE`, `VERSION`, `QUERY_LOG` and `DOMAIN_PACKAGE_NAME`.

Make sure that `QUERY_LOG` is set to false.

**`GreenDAO`** Search the source code for the following keywords:

- `import org.greenrobot.greendao.annotation.Convert`
- `import org.greenrobot.greendao.annotation.Entity`
- `import org.greenrobot.greendao.annotation.Generated`
- `import org.greenrobot.greendao.annotation.Id`
- `import org.greenrobot.greendao.annotation.Index`
- `import org.greenrobot.greendao.annotation.NotNull`
- `import org.greenrobot.greendao.annotation.*`
- `import org.greenrobot.greendao.database.Database`
- `import org.greenrobot.greendao.query.Query`

**`ActiveAndroid`** Search the source code for the following keywords:

- `ActiveAndroid.initialize(<contextReference>);`
- `import com.activeandroid.Configuration`
- `import com.activeandroid.query.*`

**`Realm`** Search the source code for the following keywords:

- `import io.realm.RealmObject;`
- `import io.realm.annotations.PrimaryKey;`

#### Parcelable

Make sure that appropriate security measures are taken when sensitive information is stored in an Intent via a Bundle that contains a Parcelable. Use explicit Intents and verify proper additional security controls when using application-level IPC (e.g., signature verification, intent-permissions, crypto).

### Dynamic Analysis

There are several ways to perform dynamic analysis:

1. For the actual persistence: Use the techniques described in the data storage chapter.
2. For reflection-based approaches: Use Xposed to hook into the deserialization methods or add unprocessable information to the serialized objects to see how they are handled (e.g., whether the application crashes or extra information can be extracted by enriching the objects).

### Testing WebViews Cleanup (MSTG-PLATFORM-10)

#### Overview

Clearing the WebView resources is a crucial step when an app accesses any sensitive data within a WebView. This includes any files stored locally, the RAM cache and any loaded JavaScript.

As an additional measure, you could use server-side headers such as `no-cache`, which prevent an application from caching particular content.

> Starting on Android 10 (API level 29) apps are able to detect if a WebView has become [unresponsive](https://developer.android.com/about/versions/10/features?hl=en#webview-hung "WebView hung renderer detection"). If this happens, the OS will automatically call the `onRenderProcessUnresponsive` method.

You can find more security best practices when using WebViews on [Android Developers](https://developer.android.com/training/articles/security-tips?hl=en#WebView "Security Tips - Use WebView").

#### Static Analysis

There are a couple of areas where an app can be deleting WebView related data. You should inspect all related APIs and try to fully track data deletion.

- **WebView APIs**:
  - **Initialization**: an app might be initializing the WebView in a way to avoid storing certain information by using `setDomStorageEnabled`, `setAppCacheEnabled` or `setDatabaseEnabled` from [`android.webkit.WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings "WebSettings"). The DOM Storage (for using the HTML5 local storage), Application Caches and Database Storage APIs are disabled by default, but apps might set these settings explicitly to "false".
  - **Cache**: Android's WebView class offers the [`clearCache`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean) "clearCache in WebViews") method which can be used to clear the cache for all WebViews used by the app. It receives a boolean input parameter (`includeDiskFiles`) which will wipe all stored resource including the RAM cache. However if it's set to false, it will only clear the RAM cache. Check the source code for usage of the `clearCache` method and verify its input parameter. Additionally, you may also check if the app is overriding `onRenderProcessUnresponsive` for the case when the WebView might become unresponsive, as the `clearCache` method might also be called from there.

- **WebStorage APIs**: [`WebStorage.deleteAllData`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData) can be also used to clear all storage currently being used by the JavaScript storage APIs, including the Web SQL Database and the HTML5 Web Storage APIs.
  > Some apps will _need_ to enable the DOM storage in order to display some HTML5 sites that use local storage. This should be carefully investigated as this might contain sensitive data.

- **Cookies**: any existing cookies can be deleted by using [CookieManager.removeAllCookies](https://developer.android.com/reference/android/webkit/CookieManager#removeAllCookies(android.webkit.ValueCallback%3Cjava.lang.Boolean%3E)).

- **File APIs**: proper data deletion in certain directories might not be that straightforward, some apps use a pragmatic solution which is to _manually_ delete selected directories known to hold user data. This can be done using the `java.io.File` API such as [`java.io.File.deleteRecursively`](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.io/java.io.-file/delete-recursively.html).

**Example:**

This example in Kotlin from the [open source Firefox Focus](https://github.com/mozilla-mobile/focus-android/blob/v8.17.1/app/src/main/java/org/mozilla/focus/webview/SystemWebView.kt#L220 "Firefox Focus for Android") app shows different cleanup steps:

```Java
override fun cleanup() {
        clearFormData() // Removes the autocomplete popup from the currently focused form field, if present. Note this only affects the display of the autocomplete popup, it does not remove any saved form data from this WebView's store. To do that, use WebViewDatabase#clearFormData.
        clearHistory()
        clearMatches()
        clearSslPreferences()
        clearCache(true)

        CookieManager.getInstance().removeAllCookies(null)

        WebStorage.getInstance().deleteAllData() // Clears all storage currently being used by the JavaScript storage APIs. This includes the Application Cache, Web SQL Database and the HTML5 Web Storage APIs.

        val webViewDatabase = WebViewDatabase.getInstance(context)
        // It isn't entirely clear how this differs from WebView.clearFormData()
        @Suppress("DEPRECATION")
        webViewDatabase.clearFormData() // Clears any saved data for web forms.
        webViewDatabase.clearHttpAuthUsernamePassword()

        deleteContentFromKnownLocations(context) // calls FileUtils.deleteWebViewDirectory(context) which deletes all content in "app_webview".
    }
```

The function finishes doing some extra _manual_ file deletion in `deleteContentFromKnownLocations` which calls functions from [`FileUtils`](https://github.com/mozilla-mobile/focus-android/blob/v8.17.1/app/src/main/java/org/mozilla/focus/utils/FileUtils.kt). These functions use the [`java.io.File.deleteRecursively`](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.io/java.io.-file/delete-recursively.html) method to recursively delete files from the specified directories.

```Java
private fun deleteContent(directory: File, doNotEraseWhitelist: Set<String> = emptySet()): Boolean {
    val filesToDelete = directory.listFiles()?.filter { !doNotEraseWhitelist.contains(it.name) } ?: return false
    return filesToDelete.all { it.deleteRecursively() }
}
```

#### Dynamic Analysis

Open a WebView accessing sensitive data and then log out of the application. Access the application's storage container and make sure all WebView related files are deleted. The following files and folders are typically related to WebViews:

- app_webview
- Cookies
- pref_store
- blob_storage
- Session Storage
- Web Data
- Service Worker

## Testing for Overlay Attacks (MSTG-PLATFORM-9)

### Overview

Screen overlay attacks occur when a malicious application manages to put itself on top of another application which remains working normally as if it were on the foreground. The malicious app might create UI elements mimicking the look and feel and the original app or even the Android system UI. The intention is typically to make users believe that they keep interacting with the legitimate app and then try to elevate privileges (e.g by getting some permissions granted), stealthy phishing, capture user taps and keystrokes etc.

There are several attacks affecting different Android versions including:

- [**Tapjacking**](https://medium.com/devknoxio/what-is-tapjacking-in-android-and-how-to-prevent-it-50140e57bf44 "What is Tapjacking in Android and How to Prevent It") (Android 6.0 (API level 23) and lower) abuses the screen overlay feature of Android listening for taps and intercepting any information being passed to the underlying activity.
- [**Cloak & Dagger**](https://cloak-and-dagger.org/ "Cloak & Dagger") attacks affect apps targeting Android 5.0 (API level 21) to Android 7.1 (API level 25). They abuse one or both of the `SYSTEM_ALERT_WINDOW` ("draw on top") and `BIND_ACCESSIBILITY_SERVICE` ("a11y") permissions that, in case the app is installed from the Play Store, the users do not need to explicitly grant and for which they are not even notified.
- [**Toast Overlay**](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/ "Android Toast Overlay Attack: Cloak and Dagger with No Permissions") is quite similar to Cloak & Dagger but do not require specific Android permissions to be granted by users. It was closed with CVE-2017-0752 on Android 8.0 (API level 26).

Usually, this kind of attacks are inherent to an Android system version having certain vulnerabilities or design issues. This makes them challenging and often virtually impossible to prevent unless the app is upgraded targeting a safe Android version (API level).

Over the years many known malware like MazorBot, BankBot or MysteryBot have been abusing the screen overlay feature of Android to target business critical applications, namely in the banking sector. This [blog](https://www.infosecurity-magazine.com/opinions/overlay-attacks-safeguard-mobile/ "Dealing with Overlay Attacks: Adopting Built-in Security to Safeguard Mobile Experience") discusses more about this type of malware.

### Static Analysis

You can find some general guidelines about Android View security in the [Android Developer Documentation](https://developer.android.com/reference/android/view/View#security "View Security"), please be sure to read them carefully. For instance, the so-called _touch filtering_ is a common defense against tapjacking, which contributes to safeguarding users against these vulnerabilities, usually in combination with other techniques and considerations as we introduce in this section.

To start your static analysis you can check the source code for the following methods and attributes (non-exhaustive list):

- Override [`onFilterTouchEventForSecurity`](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity%28android.view.MotionEvent%29 "onFilterTouchEventForSecurity") for more fine-grained control and to implement a custom security policy for views.
- Set the layout attribute [`android:filterTouchesWhenObscured`](https://developer.android.com/reference/android/view/View#attr_android:filterTouchesWhenObscured "android:filterTouchesWhenObscured") to true or call [`setFilterTouchesWhenObscured`](https://developer.android.com/reference/android/view/View.html#setFilterTouchesWhenObscured%28boolean%29 "setFilterTouchesWhenObscured").
- Check [FLAG_WINDOW_IS_OBSCURED](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_OBSCURED "FLAG_WINDOW_IS_OBSCURED") (since API level 9) or [FLAG_WINDOW_IS_PARTIALLY_OBSCURED](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_PARTIALLY_OBSCURED "FLAG_WINDOW_IS_PARTIALLY_OBSCURED") (starting on API level 29).

Some attributes might affect the app as a whole, while others can be applied to specific components. The latter would be the case when, for example, there is a business need to specifically allow overlays while wanting to protect sensitive input UI elements. The developers might also take additional precautions to confirm the user's actual intent which might be legitimate and tell it apart from a potential attack.

As a final note, always remember to properly check the API level that app is targeting and the implications that this has. For instance, [Android 8.0 (API level 26) introduced changes](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert windows") to apps requiring `SYSTEM_ALERT_WINDOW` ("draw on top"). From this API level on, apps using `TYPE_APPLICATION_OVERLAY` will be always [shown above other windows](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert Windows") having other types such as `TYPE_SYSTEM_OVERLAY` or `TYPE_SYSTEM_ALERT`. You can use this information to ensure that no overlay attacks may occur at least for this app in this concrete Android version.

### Dynamic Analysis

Abusing this kind of vulnerability on a dynamic manner can be pretty challenging and very specialized as it closely depends on the target Android version. For instance, for versions up to Android 7.0 (API level 24) you can use the following APKs as a proof of concept to identify the existence of the vulnerabilities.  

- [Tapjacking POC](https://github.com/FSecureLABS/tapjacking-poc "Tapjacking POC"): This APK creates a simple overlay which sits on top of the testing application.
- [Invisible Keyboard](https://github.com/DEVizzi/Invisible-Keyboard "Invisible Keyboard"): This APK creates multiple overlays on the keyboard to capture keystrokes. This is one of the exploit demonstrated in Cloak and Dagger attacks.

## Testing enforced updating (MSTG-ARCH-9)

Starting from Android 5.0 (API level 21), together with the Play Core Library, apps can be forced to be updated. This mechanism is based on using the `AppUpdateManager`. Before that, other mechanisms were used, such as doing http calls to the Google Play Store, which are not as reliable as the APIs of the Play Store might change. Alternatively, Firebase could be used to check for possible forced updates as well (see this [blog](https://medium.com/@sembozdemir/force-your-users-to-update-your-app-with-using-firebase-33f1e0bcec5a "Force users to update the app using Firebase")).
Enforced updating can be really helpful when it comes to public key pinning (see the Testing Network communication for more details) when a pin has to be refreshed due to a certificate/public key rotation. Next, vulnerabilities are easily patched by means of forced updates.

Please note that newer versions of an application will not fix security issues that are living in the backends to which the app communicates. Allowing an app not to communicate with it might not be enough. Having proper API-lifecycle management is key here.
Similarly, when a user is not forced to update, do not forget to test older versions of your app against your API and/or use proper API versioning.

### Static analysis

The code sample below shows the example of an app-update:

```java
//Part 1: check for update
// Creates instance of the manager.
AppUpdateManager appUpdateManager = AppUpdateManagerFactory.create(context);

// Returns an intent object that you use to check for an update.
Task<AppUpdateInfo> appUpdateInfo = appUpdateManager.getAppUpdateInfo();

// Checks that the platform will allow the specified type of update.
if (appUpdateInfo.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE
      // For a flexible update, use AppUpdateType.FLEXIBLE
      && appUpdateInfo.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)) {



                  //...Part 2: request update
                  appUpdateManager.startUpdateFlowForResult(
                     // Pass the intent that is returned by 'getAppUpdateInfo()'.
                     appUpdateInfo,
                     // Or 'AppUpdateType.FLEXIBLE' for flexible updates.
                     AppUpdateType.IMMEDIATE,
                     // The current activity making the update request.
                     this,
                     // Include a request code to later monitor this update request.
                     MY_REQUEST_CODE);



                     //...Part 3: check if update completed successfully
 @Override
 public void onActivityResult(int requestCode, int resultCode, Intent data) {
   if (myRequestCode == MY_REQUEST_CODE) {
     if (resultCode != RESULT_OK) {
       log("Update flow failed! Result code: " + resultCode);
       // If the update is cancelled or fails,
       // you can request to start the update again in case of forced updates
     }
   }
 }

 //..Part 4:
 // Checks that the update is not stalled during 'onResume()'.
// However, you should execute this check at all entry points into the app.
@Override
protected void onResume() {
  super.onResume();

  appUpdateManager
      .getAppUpdateInfo()
      .addOnSuccessListener(
          appUpdateInfo -> {
            ...
            if (appUpdateInfo.updateAvailability()
                == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
                // If an in-app update is already running, resume the update.
                manager.startUpdateFlowForResult(
                    appUpdateInfo,
                    IMMEDIATE,
                    this,
                    MY_REQUEST_CODE);
            }
          });
}
}
```

>Source: [https://developer.android.com/guide/app-bundle/in-app-updates](https://developer.android.com/guide/app-bundle/in-app-updates "Support in-app updates")

When checking for a proper update mechanism, make sure the usage of the `AppUpdateManager` is present. If it is not yet, then this means that users might be able to remain on an older version of the application with the given vulnerabilities.
Next, pay attention to the `AppUpdateType.IMMEDIATE` use: if a security update comes in, then this flag should be used in order to make sure that the user cannot go forward with using the app without updating it.
As you can see, in part 3 of the example: make sure that cancellations or errors do end up in re-checks and that a user cannot move forward in case of a critical security update.
Finally, in part 4: you can see that for every entry point in the application, an update-mechanism should be enforced, so that bypassing it will be harder.

### Dynamic analysis

In order to test for proper updating: try downloading an older version of the application with a security vulnerability, either by a release from the developers or by using a third party app-store.
Next, verify whether or not you can continue to use the application without updating it. If an update prompt is given, verify if you can still use the application by canceling the prompt or otherwise circumventing it through normal application usage. This includes validating whether the backend will stop calls to vulnerable backends and/or whether the vulnerable app-version itself is blocked by the backend.
Lastly, see if you can play with the version number of a man-in-the-middled app and see how the backend responds to this (and if it is recorded at all for instance).

## References

### Android App Bundles and updates

- <https://developer.android.com/guide/app-bundle/in-app-updates>

### Android Fragment Injection

- <https://www.synopsys.com/blogs/software-security/fragment-injection/>
- <https://securityintelligence.com/wp-content/uploads/2013/12/android-collapses-into-fragments.pdf>

### Android Permissions Documentation

- <https://developer.android.com/training/permissions/usage-notes>
- <https://developer.android.com/training/permissions/requesting#java>
- <https://developer.android.com/guide/topics/permissions/overview#permission-groups>
- <https://developer.android.com/guide/topics/manifest/provider-element#gprmsn>
- <https://developer.android.com/reference/android/content/Context#revokeUriPermission(android.net.Uri,%20int)>
- <https://developer.android.com/reference/android/content/Context#checkUriPermission(android.net.Uri,%20int,%20int,%20int)>
- <https://developer.android.com/guide/components/broadcasts#restricting_broadcasts_with_permissions>
- <https://developer.android.com/guide/topics/permissions/overview>
- <https://developer.android.com/guide/topics/manifest/manifest-intro#filestruct>

### Android Bundles and Instant Apps

- <https://developer.android.com/topic/google-play-instant/getting-started/instant-enabled-app-bundle>
- <https://developer.android.com/topic/google-play-instant/guides/multiple-entry-points>
- <https://developer.android.com/studio/projects/dynamic-delivery>

### Android permissions changes in Android 8

- <https://developer.android.com/about/versions/oreo/android-8.0-changes>

### Android WebViews and SafeBrowsing

- <https://developer.android.com/training/articles/security-tips#WebView>
- <https://developer.android.com/guide/webapps/managing-webview#safe-browsing>
- <https://developer.android.com/about/versions/oreo/android-8.1#safebrowsing>
- <https://support.virustotal.com/hc/en-us/articles/115002146549-Mobile-Apps>

### Android Custom URL Schemes

- <https://developer.android.com/training/app-links/>
- <https://developer.android.com/training/app-links/deep-linking>
- <https://developer.android.com/training/app-links/verify-site-associations>
- <https://developers.google.com/digital-asset-links/v1/getting-started>
- <https://pdfs.semanticscholar.org/0415/59c01d5235f8cf38a3c69ccee7e1f1a98067.pdf>

### Android App Notifications

- <https://developer.android.com/guide/topics/ui/notifiers/notifications>
- <https://developer.android.com/training/notify-user/build-notification>
- <https://developer.android.com/reference/android/service/notification/NotificationListenerService>
- <https://medium.com/csis-techblog/analysis-of-joker-a-spy-premium-subscription-bot-on-googleplay-9ad24f044451>

### OWASP MASVS

- MSTG-PLATFORM-1: "The app only requests the minimum set of permissions necessary."
- MSTG-PLATFORM-2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."
- MSTG-PLATFORM-3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."
- MSTG-PLATFORM-4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."
- MSTG-PLATFORM-5: "JavaScript is disabled in WebViews unless explicitly required."
- MSTG-PLATFORM-6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."
- MSTG-PLATFORM-7: "If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package."
- MSTG-PLATFORM-8: "Object serialization, if any, is implemented using safe serialization APIs."
- MSTG-PLATFORM-10: "A WebView's cache, storage, and loaded resources (JavaScript, etc.) should be cleared before the WebView is destroyed."
- MSTG-ARCH-9: "A mechanism for enforcing updates of the mobile app exists."
