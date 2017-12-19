## Android Platform APIs

### Testing App Permissions

#### Overview

Android assigns every installed app with a distinct system identity (Linux user ID and group ID). Because each Android app operates in a process sandbox, apps must explicitly request access to resources and data outside their sandbox. They request this access by declaring the permissions they need to use certain system data and features. Depending on how sensitive or critical the data or feature is, Android system will grant the permission automatically or ask the user to approve the request.

Android permissions are classified in four different categories based on the protection level it offers.

-	**Normal**: This permission gives apps access to isolated application-level features, with minimal risk to other apps, the user or the system. It is granted during the installation of the App. If no protection level is specified, normal is the default value. Example: `android.permission.INTERNET`
-	**Dangerous**: This permission usually gives the app control over user data or control over the device that impacts the user. This type of permission may not be granted at installation time, leaving it to the user to decide whether the app should have the permission or not. Example: `android.permission.RECORD_AUDIO`
-	**Signature**: This permission is granted only if the requesting app was signed with the same certificate as the app that declared the permission. If the signature matches, the permission is automatically granted. Example: `android.permission.ACCESS_MOCK_LOCATION`
-	**SystemOrSignature**: Permission only granted to applications embedded in the system image or that were signed using the same certificate as the application that declared the permission. Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`

A full list of all permissions can be found in the [Android developer documentation](https://developer.android.com/guide/topics/permissions/requesting.html "Android Permissions").

**Custom Permissions**

Android allow apps to expose their services/components to other apps and custom permissions are required to restrict which app can access the exposed component. [Custom permissions](https://developer.android.com/guide/topics/permissions/defining.html "Custom Permissions") can be defined in `AndroidManifest.xml`, by creating a permission tag with two mandatory attributes:
- `android:name` and
- `android:protectionLevel`.

It is crucial to create custom permission that adhere to the *Principle of Least Privilege*: permission should be defined explicitly for its purpose with meaningful and accurate label and description.

Below is an example of a custom permission called `START_MAIN_ACTIVITY` that is required when launching the `TEST_ACTIVITY` Activity.

The first code block defines the new permission which is self-explanatory. The label tag is a summary of the permission and description is a more detailed description of the summary. The protection level can be set based on the types of permission it is granting. Once you have defined your permission, it can be enforced on the component by specifying it in the application’s manifest. In our example, the second block is the component that we are going to restrict with the permission we created. It can be enforced by adding the `android:permission` attributes.

```xml
<permission android:name="com.example.myapp.permission.START_MAIN_ACTIVITY"
        android:label="Start Activity in myapp"
        android:description="Allow the app to launch the activity of myapp app, any app you grant this permission will be able to launch main activity by myapp app."
        android:protectionLevel="normal" />

<activity android:name="TEST_ACTIVITY"
    android:permission="com.example.myapp.permission.START_MAIN_ACTIVITY">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER"/>
     </intent-filter>
</activity>
```

Now that the new permission `START_MAIN_ACTIVTY` is created, apps can request it using the `uses-permission` tag in the `AndroidManifest.xml` file. Any application can now launch the `TEST_ACTIVITY` if it is granted with the custom permission `START_MAIN_ACTIVITY`.

```xml
<uses-permission android:name=“com.example.myapp.permission.START_MAIN_ACTIVITY”/>
```

#### Static Analysis


**Android Permissions**

Permissions should be checked if they are really needed within the App and removed otherwise. For example in order for an Activity to load a web page into a WebView the `INTERNET` permission in the Android Manifest file is needed.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

It is always recommended to run through the permissions with the developer together to identify the intention of every permission set and remove those that are not needed.

Alternatively, Android Asset Packaging tool can be used to examine permissions.

```bash
$ aapt d permissions com.owasp.mstg.myapp
uses-permission: android.permission.WRITE_CONTACTS
uses-permission: android.permission.CHANGE_CONFIGURATION
uses-permission: android.permission.SYSTEM_ALERT_WINDOW
uses-permission: android.permission.INTERNAL_SYSTEM_WINDOW
```

**Custom Permissions**

Apart from enforcing custom permissions via application manifest file, they can also be checked programmatically. This is not recommended however, as it is more error prone and can be bypassed more easily, e.g. using runtime instrumentation. Whenever you see code like the following, you should also make sure that the same permissions are enforced in the manifest file.

```java
int canProcess = checkCallingOrSelfPermission(“com.example.perm.READ_INCOMING_MSG”);
if (canProcess != PERMISSION_GRANTED)
throw new SecurityException();
```

#### Dynamic Analysis

Permissions of applications installed on a device can be retrieved using Drozer. The following extract demonstrates how to examine the permissions used by an application, in addition to the custom permissions defined by the app:

```bash
dz> run app.package.info  -a com.android.mms.service
Package: com.android.mms.service
  Application Label: MmsService
  Process Name: com.android.phone
  Version: 6.0.1
  Data Directory: /data/user/0/com.android.mms.service
  APK Path: /system/priv-app/MmsService/MmsService.apk
  UID: 1001
  GID: [2001, 3002, 3003, 3001]
  Shared Libraries: null
  Shared User ID: android.uid.phone
  Uses Permissions:
  - android.permission.RECEIVE_BOOT_COMPLETED
  - android.permission.READ_SMS
  - android.permission.WRITE_SMS
  - android.permission.BROADCAST_WAP_PUSH
  - android.permission.BIND_CARRIER_SERVICES
  - android.permission.BIND_CARRIER_MESSAGING_SERVICE
  - android.permission.INTERACT_ACROSS_USERS
  Defines Permissions:
  - None
```

When Android applications expose IPC components to other applications, they can define permissions to limit access to the component to certain applications. To communicate with a component protected by a `normal` or `dangerous` permission, Drozer can be rebuilt to contain the required permission:

```
$ drozer agent build  --permission android.permission.REQUIRED_PERMISSION
```

Note that this method cannot be used for `signature` level permissions, as Drozer would need to be signed by the same certificate as the target application.


### Testing Custom URL Schemes

#### Overview

Both Android and iOS allow inter-app communication through the use of custom URL schemes. These custom URLs allow other applications to perform specific actions within the application hosting the custom URL scheme. Much like a standard web URL that might start with `https://`, custom URIs can begin with any scheme prefix and usually define an action to take within the application and parameters for that action.

As a contrived example, consider: `sms://compose/to=your.boss@company.com&message=I%20QUIT!&sendImmediately=true`. When a victim clicks such a link on a web page in their mobile browser, the vulnerable SMS application will send the SMS message with the maliciously crafted content. This could lead to:

- financial loss for the victims if messages are sent to premium services or
- disclosing the phone number if messages are sent to predefined addresses that collect phone numbers.

Once a URL scheme is defined, multiple apps can register for any available scheme. For any application, each of these custom URL schemes needs to be enumerated, and the actions they perform need to be tested.

URL schemes can be used for [deep linking](http://mobiledeeplinking.org "Mobile Deeplinking"), which is a widespread and convenient method for launching a native mobile app via a link and doesn't represent a risk by itself.

Nevertheless data coming in through URL schemes which is processed by the app should be validated, as described in the test case "Testing Input Validation and Sanitization".

#### Static Analysis

Investigate if custom URL schemes are defined. This can be done in the AndroidManifest file inside of an [intent-filter element](https://developer.android.com/guide/components/intents-filters.html#DataTest "Custom URL scheme").

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

The example above is specifying a new URL scheme called `myapp://`. The category `browsable` will allow to open the URI within a browser.

Data can then be transmitted trough this new scheme, by using for example the following URI: `myapp://path/to/what/i/want?keyOne=valueOne&keyTwo=valueTwo`. Code like the following can be used to retrieve the data:

```Java
Intent intent = getIntent();
if (Intent.ACTION_VIEW.equals(intent.getAction())) {
  Uri uri = intent.getData();
  String valueOne = uri.getQueryParameter("keyOne");
  String valueTwo = uri.getQueryParameter("keyTwo");
}
```

Verify also the usage of [`toUri`](https://developer.android.com/reference/android/content/Intent.html#toUri%28int%29 "Intent.toUri()"), that might also be used in this context.

#### Dynamic Analysis

To enumerate URL schemes within an app that can be called by a web browser, the Drozer module `scanner.activity.browsable` should be used:

```
dz> run scanner.activity.browsable -a com.google.android.apps.messaging
Package: com.google.android.apps.messaging
  Invocable URIs:
    sms://
    mms://
  Classes:
    com.google.android.apps.messaging.ui.conversation.LaunchConversationActivity
```

Custom URL schemes can be called using the Drozer module `app.activity.start`:

```
dz> run app.activity.start  --action android.intent.action.VIEW --data-uri "sms://0123456789"
```

When calling a defined schema (myapp://someaction/?var0=string&var1=string), it might be used to send data to the app as in the example below.

```Java
Intent intent = getIntent();
if (Intent.ACTION_VIEW.equals(intent.getAction())) {
  Uri uri = intent.getData();
  String valueOne = uri.getQueryParameter("var0");
  String valueTwo = uri.getQueryParameter("var1");
}
```

Defining your own URL scheme and using it can become a risk in this case, if data is sent to it from an external party and processed in the app.

### Testing For Sensitive Functionality Exposure Through IPC

#### Overview

During development of a mobile application, traditional techniques for IPC might be applied like usage of shared files or network sockets. As mobile application platforms implement their own system functionality for IPC, these mechanisms should be applied as they are much more mature than traditional techniques. Using IPC mechanisms with no security in mind may cause the application to leak or expose sensitive data.

The following is a list of Android IPC Mechanisms that may expose sensitive data:

-  [Binders](https://developer.android.com/reference/android/os/Binder.html "IPCBinder")
-  [Services](https://developer.android.com/guide/components/services.html "IPCServices")
-  [Bound Services](https://developer.android.com/guide/components/bound-services.html "BoundServices")
-  [AIDL](https://developer.android.com/guide/components/aidl.html "AIDL")
-  [Intents](https://developer.android.com/reference/android/content/Intent.html "IPCIntent")
-  [Content Providers](https://developer.android.com/reference/android/content/ContentProvider.html "IPCContentProviders")

#### Static Analysis

We start by looking at the AndroidManifest, where all activities, services and content providers included in the source code must be declared (otherwise the system will not recognize them and they will not run). However, broadcast receivers can be either declared in the manifest or created dynamically. You will want to identify elements such as:

-	[`<intent-filter>`](https://developer.android.com/guide/topics/manifest/intent-filter-element.html "IntentFilterElement")
-	[`<service>`](https://developer.android.com/guide/topics/manifest/service-element.html "ServiceElement")
-	[`<provider>`](https://developer.android.com/guide/topics/manifest/provider-element.html "ProviderElement")
-	[`<receiver>`](https://developer.android.com/guide/topics/manifest/receiver-element.html "ReceiverElement")

Making an activity, service or content provided as "exported" means that it can be accessed by other apps. There are two common ways to set a component as exported. The obvious one is to set the export tag to true `android:exported="true"`. The second way is to define an `<intent-filter>` within the component element (`<activity>`, `<service>`, `<receiver>`). When doing this, the export tag is automatically set to "true". If not strictly required, be sure that the IPC component element does not have the `android:exported="true"` value in the `AndroidManifest.xml` file nor an `<intent-filter>`, to prevent all other apps on Android from being able to interact with it.

Apart from that, remember that using the permission tag (`android:permission`) will also limit the exposure of a component to other applications. If your IPC is intended to be accessible to other applications, you can apply a security policy by using the `<permission>` element and set a proper `android:protectionLevel`. When using `android:permission` in a service declaration, other applications will need to declare a corresponding `<uses-permission>` element in their own manifest to be able to start, stop, or bind to the service.

For more information about the content providers, please refer to the test case "Testing Whether Stored Sensitive Data Is Exposed via IPC Mechanisms" in chapter "Testing Data Storage".

Once you identify a list of IPC mechanisms, review the source code in order to detect if they leak any sensitive data when used. For example, content providers can be used to access database information, while services can be probed to see if they return data. Also broadcast receivers can leak sensitive information if probed or sniffed.

In the following we will use two example apps and give examples on how to identify vulnerable IPC components:

- ["Sieve"](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk "Sieve: Vulnerable Password Manager")
- ["Android Insecure Bank"](https://github.com/dineshshetty/Android-InsecureBankv2 "Android Insecure Bank V2")

##### Activities

##### Inspect the AndroidManifest

In the "Sieve" app we can find three exported activities identified by `<activity>`:

```xml
<activity android:excludeFromRecents="true" android:label="@string/app_name" android:launchMode="singleTask" android:name=".MainLoginActivity" android:windowSoftInputMode="adjustResize|stateVisible">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:finishOnTaskLaunch="true" android:label="@string/title_activity_file_select" android:name=".FileSelectActivity"/>
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:finishOnTaskLaunch="true" android:label="@string/title_activity_pwlist" android:name=".PWList"/>

```

##### Inspect the source code

By inspecting the `PWList.java` activity we see that it offers options to list all keys, add, delete, etc. If we invoke it directly we will be able to bypass the LoginActivity. More on this can be found below in the dynamic analysis.

##### Services

##### Inspect the AndroidManifest

In the "Sieve" app we can find two exported services identified by `<service>`:

```xml
<service android:exported="true" android:name=".AuthService" android:process=":remote"/>
<service android:exported="true" android:name=".CryptoService" android:process=":remote"/>
```

##### Inspect the source code

Check the source code for the class `android.app.Service`:

By reversing the target application, we can see the service `AuthService` provides functionality to change the password and PIN protecting the target app.

```
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
```

##### Broadcast Receivers

##### Inspect the AndroidManifest

In "Android Insecure Bank" app we can find a broadcast receiver in the manifest identified by `<receiver>`:

```xml
<receiver android:exported="true" android:name="com.android.insecurebankv2.MyBroadCastReceiver">
    <intent-filter>
        <action android:name="theBroadcast"/>
    </intent-filter>
</receiver>
```

##### Inspect the source code

Search in the source code for strings like `sendBroadcast`, `sendOrderedBroadcast`, `sendStickyBroadcast` and verify that the application doesn't send any sensitive data.

If an Intent is only broadcast/received in the same application, `LocalBroadcastManager` can be used so that, by design, other apps cannot receive the broadcast message. This reduces the risk of leaking sensitive information. `LocalBroadcastManager.sendBroadcast()`.

In order to know more about what the receiver is intended to do we have to go deeper in our static analysis and search for usages of the class `android.content.BroadcastReceiver` and the `Context.registerReceiver()` method used to dynamically create receivers.

In the extract below taken from the source code of the target application, we can see that the broadcast receiver triggers a SMS message to be sent containing the decrypted password of the user.

```
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
```

BroadcastReceivers should make use of the `android:permission` attribute, as otherwise any other application can invoke them. `Context.sendBroadcast(intent, receiverPermission);` can be used to specify permissions a receiver needs to be able to [read the broadcast](https://developer.android.com/reference/android/content/Context.html#sendBroadcast(android.content.Intent\ "SendBroadcast")). You can also set an explicit application package name that limits the components this Intent will resolve to. If left to the default value of null, all components in all applications will considered. If non-null, the Intent can only match the components in the given application package.


#### Dynamic Analysis

IPC components can be enumerated using Drozer. To list all exported IPC components, the module `app.package.attacksurface` should be used:

```
dz> run app.package.attacksurface com.mwr.example.sieve
Attack Surface:
  3 activities exported
  0 broadcast receivers exported
  2 content providers exported
  2 services exported
    is debuggable
```

##### Content Providers

The "Sieve" application implements a vulnerable content provider. To list of content providers exported by the Sieve app execute the following command:

```
dz> run app.provider.finduri com.mwr.example.sieve
Scanning com.mwr.example.sieve...
content://com.mwr.example.sieve.DBContentProvider/
content://com.mwr.example.sieve.FileBackupProvider/
content://com.mwr.example.sieve.DBContentProvider
content://com.mwr.example.sieve.DBContentProvider/Passwords/
content://com.mwr.example.sieve.DBContentProvider/Keys/
content://com.mwr.example.sieve.FileBackupProvider
content://com.mwr.example.sieve.DBContentProvider/Passwords
content://com.mwr.example.sieve.DBContentProvider/Keys
```

Content providers with names like "Passwords" and "Keys" are prime suspects for sensitive information leaks. After all, it wouldn't be great if sensitive keys and passwords could simply be queried from the provider!

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys
Permission Denial: reading com.mwr.example.sieve.DBContentProvider uri content://com.mwr.example.sieve.DBContentProvider/Keys from pid=4268, uid=10054 requires com.mwr.example.sieve.READ_KEYS, or grantUriPermission()
```

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/
| Password          | pin  |
| SuperPassword1234 | 1234 |
```

This content provider can be accessed without any permission.

```
dz> run app.provider.update content://com.mwr.example.sieve.DBContentProvider/Keys/ --selection "pin=1234" --string  Password "newpassword"
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/
| Password    | pin  |
| newpassword | 1234 |
```

##### Activities

To list activities exported by an application the module `app.activity.info` should be used. Specify the target package with `-a` or leave blank to target all apps on the device:

```
dz> run app.activity.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.FileSelectActivity
    Permission: null
  com.mwr.example.sieve.MainLoginActivity
    Permission: null
  com.mwr.example.sieve.PWList
    Permission: null  
```

By enumerating activities in the vulnerable password manager "Sieve", the activity `com.mwr.example.sieve.PWList` is found to be exported with no required permissions. It is possible to use the module `app.activity.start` to launch this activity.

```
dz> run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList
```

Since the activity was called directly, the login form protecting the password manager was bypassed, and the data contained within the password manager could be accessed.

##### Services

Services can be enumerated using the Drozer module `app.service.info`:

```
dz> run app.service.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.AuthService
    Permission: null
  com.mwr.example.sieve.CryptoService
    Permission: null
```

To communicate with a service, static analysis must first be used to identify the required inputs.

Since this service is exported, it is possible to use the module `app.service.send` to communicate with the service and change the password stored in the target application:

```
dz> run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg  6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj
Got a reply from com.mwr.example.sieve/com.mwr.example.sieve.AuthService:
  what: 4
  arg1: 42
  arg2: 0
  Empty
```

##### Broadcast Receivers

Broadcasts can be enumerated using the Drozer module `app.broadcast.info`, the target package should be specified using the `-a` parameter:

```
dz> run app.broadcast.info -a com.android.insecurebankv2
Package: com.android.insecurebankv2
  com.android.insecurebankv2.MyBroadCastReceiver
    Permission: null
```

In the example app "Android Insecure Bank", we can see that one broadcast receiver is exported, not requiring any permissions, indicating that we can formulate an intent to trigger the broadcast receiver. When testing broadcast receivers, static analysis must also be used to understand the functionality of the broadcast receiver as we did before.

Using the Drozer module `app.broadcast.send`, it is possible to formulate an intent to trigger the broadcast and send the password to a phone number within our control:

```
dz>  run app.broadcast.send --action theBroadcast --extra string phonenumber 07123456789 --extra string newpass 12345
```

This generates the following SMS:

```
Updated Password from: SecretPassword@ to: 12345
```

###### Sniffing Intents

If an Android application broadcasts intents without setting a required permission or specifying the destination package, the intents are susceptible to monitoring by any application on the device.

To register a broadcast receiver to sniff intents, the Drozer module `app.broadcast.sniff` should be used, specifying the action to monitor with the `--action` parameter:

```
dz> run app.broadcast.sniff  --action theBroadcast
[*] Broadcast receiver registered to sniff matching intents
[*] Output is updated once a second. Press Control+C to exit.

Action: theBroadcast
Raw: Intent { act=theBroadcast flg=0x10 (has extras) }
Extra: phonenumber=07123456789 (java.lang.String)
Extra: newpass=12345 (java.lang.String)
```


### Testing JavaScript Execution in WebViews

#### Overview

In web applications, JavaScript can be injected in many ways by leveraging reflected, stored or DOM based Cross-Site Scripting (XSS). Mobile apps are executed in a sandboxed environment and when implemented natively do not possess this attack vector. Nevertheless, WebViews can be part of a native app to allow viewing of web pages. Every app has it's own cache for WebViews and doesn't share it with the native Browser or other apps. WebViews in Android are using the WebKit rendering engine to display web pages but are stripped down to a minimum of functions, as for example no address bar is available. If the WebView is implemented too lax and allows the usage of JavaScript it can be used to attack the app and gain access to it's data.

#### Static Analysis

The source code need to be checked for usage and implementations of the WebView class. To create and use a WebView, an instance of the class WebView need to be created.

```Java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("https://www.owasp.org/");
```

Different settings can be applied to the WebView of which one is to activate and deactivate JavaScript. By default JavaScript is disabled in a WebView, so it need to be explicitly enabled. Look for the method [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled(boolean\) "setJavaScriptEnabled in WebViews") to check if JavaScript is activated.

```Java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript. It should only be enabled if needed to reduce the attack surface and potential threats to the app. If JavaScript is needed it should be ensured:

- that the communication relies consistently on HTTPS to protect HTML and JavaScript from tampering while in transit.
- that JavaScript and HTML is only loaded locally from within the app data directory or from trusted web servers.

The cache of the WebView should also be cleared in order to remove all JavaScript and locally stored data, by using [`clearCache()`](https://developer.android.com/reference/android/webkit/WebView.html#clearCache(boolean\) "clearCache() in WebViews") when closing the App.

Devices running platforms older than Android 4.4 (API level 19) use a version of Webkit that has a number of security issues. As a workaround, if the app is supporting these devices, it must confirm that WebView objects [display only trusted content](https://developer.android.com/training/articles/security-tips.html#WebView "WebView Best Practices").

#### Dynamic Analysis

A Dynamic Analysis depends on different surrounding conditions, as there are different possibilities to inject JavaScript into a WebView of an app:

- Stored Cross-Site Scripting (XSS) vulnerabilities in an endpoint, where the exploit will be sent to the WebView of the mobile app when navigating to the vulnerable function.
- Man-in-the-middle (MITM) position by an attacker where he is able to tamper the response by injecting JavaScript.
- Malware tampering local files that are loaded by the WebView.

In order to address these attack vectors, the outcome of the following checks should be verified:

- All functions offered by the endpoint need to be free of [stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002\) "Stored Cross-Site Scripting").
- The HTTPS communication need to be implemented according to best practices to avoid MITM attacks. This means:
  - whole communication is encrypted via TLS (see test case "Testing for Unencrypted Sensitive Data on the Network"),
  - the certificate is checked properly (see test case "Testing Endpoint Identify Verification") and/or
  - the certificate is even pinned (see "Testing Custom Certificate Stores and SSL Pinning")
- Only files within the app data directory should be rendered in a WebView (see test case "Testing for Local File Inclusion in WebViews").

### Testing WebView Protocol Handlers

#### Overview

Several [schemas](https://developer.android.com/guide/appendix/g-app-intents.html "Intent List") are available by default in an URI on Android and can be triggered within a WebView, e.g:

-	http(s)://
-	file://
-	tel://

WebViews can load content remotely, but can also load it locally from the app data directory or external storage. If the content is loaded locally it should not be possible by the user to influence the filename or path where the file is loaded from or should be able to edit the loaded file.

#### Static Analysis

Check the source code for the usage of WebViews. The following [WebView settings](https://developer.android.com/reference/android/webkit/WebSettings.html "WebView Settings") are available to control access to different resources:

-	`setAllowContentAccess()`: Content URL access allows WebView to load content from a content provider installed in the system. The default is enabled.
-	`setAllowFileAccess()`: Enables or disables file access within a WebView. File access is enabled by default. Note that this enables or disables [file system access](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29 "File Access in WebView") only. Assets and resources are still accessible using `file:///android_asset` and `file:///android_res`.
-	`setAllowFileAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from other file scheme URLs. The default value is true for API level 15 (Ice Cream Sandwich) and below, and false for API level 16 (Jelly Bean) and above.
-	`setAllowUniversalAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from any origin. The default value is true for API level 15 (Ice Cream Sandwich) and below, and false for API level 16 (Jelly Bean) and above.

If one or all of the methods above can be identified and they are activated it should be verified if it is really needed for the app to work properly.

If a WebView instance can be identified check if local files are loaded through the method [`loadURL()`](https://developer.android.com/reference/android/webkit/WebView.html#loadUrl(java.lang.String\) "loadURL() in WebView").

```Java
WebView webview = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

It needs to be verified where the HTML file is loaded from. For example if it's loaded from the external storage the file is read and writable by everybody and considered a bad practice. Instead they should be placed in the assets directory of the App.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in `loadURL()` should be checked, if any dynamic parameters are used that can be manipulated, which may lead to local file inclusion.

Set the following [code snippet and best practices](https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation "WebView best practices") in order to deactivate protocol handlers, if applicable:

```java
//Should an attacker somehow find themselves in a position to inject script into a WebView, then they could exploit the opportunity to access local resources. This can be somewhat prevented by disabling local file system access. It is enabled by default. The Android WebSettings class can be used to disable local file system access via the public method setAllowFileAccess.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

- Create a white-list that defines the web pages and it's protocols that are allowed to be loaded locally and remotely.
- Create checksums of the local HTML/JavaScript files and check it during start up of the App. Minify JavaScript files in order to make it harder to read them.

#### Dynamic Analysis

While using the app look for ways to trigger phone calls or accessing files from the file system to identify usage of protocol handlers.


### Testing Whether Java Objects Are Exposed Through WebViews

#### Overview

Android offers a way that enables JavaScript executed in a WebView to call and use native functions within an Android App called [`addJavascriptInterface()`](https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface%28java.lang.Object,%20java.lang.String%29 "Method addJavascriptInterface()").

The `addJavascriptInterface()` method allows to expose Java Objects to WebViews. When using this method in an Android app it is possible for JavaScript code in a WebView to invoke native methods of the Android App.

Before Android 4.2 Jelly Bean (API Level 17) [a vulnerability was discovered](https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/ "WebView addJavascriptInterface Remote Code Execution") in the implementation of `addJavascriptInterface()`, by using reflection that leads to remote code execution when injecting malicious JavaScript in a WebView.

With API Level 17 this vulnerability was fixed and the access granted to methods of a Java Object for JavaScript was changed. When using `addJavascriptInterface()`, methods of a Java Object are only accessible for JavaScript when the annotation `@JavascriptInterface` is explicitly added. Before API Level 17 all methods of the Java Object were accessible by default.

An app that is targeting an Android version before Android 4.2 is still vulnerable to the identified flaw in `addJavascriptInterface()` and should only be used with extreme care. Therefore several best practices should be applied in case this method is needed.

#### Static Analysis

It need to be verified if and how the method `addJavascriptInterface()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example shows how `addJavascriptInterface` is used in a WebView to bridge a Java Object to JavaScript:

```Java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android API level 17 and above, an annotation called `JavascriptInterface` is used to explicitly allow the access from JavaScript to a Java method.

```Java
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

If the annotation `@JavascriptInterface` is used, this method can be called from JavaScript. If the app is targeting API level < 17, all methods of the Java Object are exposed to JavaScript and can be called.

In JavaScript the method `returnString()` can now be called and the return value can be stored in the parameter `result`.

```Javascript
var result = window.Android.returnString();
```

If an attacker has access to the JavaScript code, for example through stored XSS or a MITM attack, he can directly call the exposed Java methods in order to exploit them.

If `addJavascriptInterface()` is needed, only JavaScript provided with the APK should be allowed to call it but no JavaScript loaded from remote endpoints.

Another compliant solution is to define the API level to 17 (JELLY_BEAN_MR1) and above in the manifest file of the app. For these API levels, only public methods that are [annotated with `JavascriptInterface`](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=129859614 "DRD13 addJavascriptInterface()") can be accessed from JavaScript.

```xml
<uses-sdk android:minSdkVersion="17" />
...

</manifest>
```

#### Dynamic Analysis

The dynamic analysis of the app can determine what HTML or JavaScript files are loaded and if known vulnerabilities are present. The procedure to exploit the vulnerability is to produce a JavaScript payload and then inject it into the file that the app is requesting for. The injection could be done either though a MITM attack, or by modifying directly the file in case it is stored on the external storage. The whole process could be done through Drozer that using weasel (MWR's advanced exploitation payload) which is able to install a full agent, injecting a limited agent into a running process, or connecting a reverse shell to act as a Remote Access Tool (RAT).

A full description of the attack can be found in the [blog article by MWR](https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/ "WebView addJavascriptInterface Remote Code Execution").


### Testing Object Persistence

#### Overview

There are various ways to persist an object within Android:

##### Object Serialization

An object and its data can be represented as a sequence of bytes. In Java, this is possible using [object serialization](https://developer.android.com/reference/java/io/Serializable.html "Serializable"). Serialization is not secure by default and is just a binary format or representation that can be used to store data locally as .ser file. It is possible to encrypt and sign/HMAC serialized data as long as the keys are stored safely. To deserialize an object, the same version of the class is needed as when it was serialized. When classes are changed, the `ObjectInputStream` will not be able to create objects from older .ser files. The example below shows how to create a `Serializable` class by implementing the `Serializable` interface.

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

Now in another class, you can read/write the object using an `ObjectInputStream`/`ObjectOutputStream`.

##### JSON

There are various ways to serialize the contents of an object to JSON. Android comes with the `JSONObject` and `JSONArray` classes. Next there is a wide variety of libraries which can be used, such as [GSON](https://github.com/google/gson "Google Gson") or [Jackson](https://github.com/FasterXML/jackson-core "Jackson core"). They mostly differ in whether they use reflection to compose the object, whether they support annotations and the amount of memory they use. Note that almost all the JSON representations are String based and therefore immutable. This means that any secret stored in JSON will be harder to remove from memory. JSON itself can be stored somewhere, e.g. (NoSQL) database or a file. You just need to make sure that any JSON that contains secrets has been appropriately protected (e.g. encrypted/HMACed). See the data storage chapter for more details. Here is a simple example of how JSON can be written and read using GSON from the GSON User Guide. In this sample, the contents of an instance of the `BagOfPrimitives` is serialized into JSON:

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

##### ORM

There are libraries that provide the functionality to store the contents of an object directly into a database and then instantiate the objects based on the database content again. This is called Object-Relational Mapping (ORM). There are libraries that use SQLite as a database, such as:
- [OrmLite](http://ormlite.com/ "OrmLite"),
- [SugarORM](http://satyan.github.io/sugar/ "Sugar ORM"),
- [GreenDAO](http://greenrobot.org/greendao/ "GreenDAO") and
- [ActiveAndroid](http://www.activeandroid.com/ "ActiveAndroid").

[Realm](https://realm.io/docs/java/latest/ "Realm Java") on the other hand, uses its own database to store the contents of a class. The amount of protection that ORM can provide mostly relies on whether the database is encrypted. See the data storage chapter for more details. A nice [example of ORM Lite](https://github.com/j256/ormlite-examples/tree/master/android/HelloAndroid "OrmLite example") can be found on their website.

##### Parcelable

[`Parcelable`](https://developer.android.com/reference/android/os/Parcelable.html "Parcelable") is an interface for classes whose instances can be written to and restored from a [`Parcel`](https://developer.android.com/reference/android/os/Parcel.html "Parcel"). A parcel is often used to pack a class as part of a `Bundle` content for an `Intent`. Here's an example from the Android developer documentation that implements `Parcelable`:

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

As the mechanisms with Parcels and Intents might change over time, and the `Parcelable` might contain `IBinder` pointers, it is not recommended to store any data on disk using `Parcelable`.

#### Static Analysis

In general: if the object persistence is used for persisting any sensitive information on the device, then make sure that the information is encrypted and signed/HMACed. See the chapters on data storage and cryptographic management for more details. Next, you need to make sure that obtaining the keys to decrypt and verify are only obtainable if the user is authenticated. Security checks should be made at the correct positions as defined in [best practices](https://www.securecoding.cert.org/confluence/display/java/SER04-J.+Do+not+allow+serialization+and+deserialization+to+bypass+the+security+manager "SER04-J. Do not allow serialization and deserialization to bypass the security manager").

There are a few generic remediation steps one can always take:

1.	Make sure that sensitive data after serialization/persistence has been encrypted and HMACed/signed. Evaluate the signature or HMAC before you use the data. See the chapter about cryptography for more details.
2.	Make sure that keys used for step 1 cannot be extracted easily. Instead, the user and/or application instance should be properly authenticated/authorized to obtain the keys to use the data. See the data storage chapter for more details.
3.	Make sure that the data within the de-serialized object is carefully validated before it is actively used (e.g. no exploit of business/application logic).

In case of a high-risk application with a focus on availability, we would recommend to only use `Serializable` when the classes that are serialized are stable. Second, we would recommend to rather not use reflection based persistence because:

- The attacker could possibly find the signature of the method due to the String based argument
- The attacker might be able to manipulate the reflection based steps in order to execute business logic.

See the anti-reverse-engineering chapter for more details.

##### Object Serialization

Search the source code for the following keywords:

-	`import java.io.Serializable`
-	`implements Serializable`

##### JSON

Static analysis depends on the library being used. In case of the need to counter memory-dumping, make sure that highly sensitive information is not stored in JSON as you cannot guarantee any anti-memory dumping techniques with the standard libraries. You can check for the following keywords per library:

**`JSONObject`** Search the source code for the following keywords:

-	`import org.json.JSONObject;`
-	`import org.json.JSONArray;`

**`GSON`** Search the source code for the following keywords:

-	`import com.google.gson`
-	`import com.google.gson.annotations`
-	`import com.google.gson.reflect`
-	`import com.google.gson.stream`
-	`new Gson();`
-	Annotations such as: `@Expose`, `@JsonAdapter`, `@SerializedName`,`@Since`, `@Until`

**`Jackson`** Search the source code for the following keywords:

-	`import com.fasterxml.jackson.core`
-	`import org.codehaus.jackson` for the older version.

##### ORM

When using an ORM library, verify that the data is stored in an encrypted database or that the class representations are individually encrypted before storing it. See the chapters on data storage and cryptographic management for more details. You can check for the following keywords per library:

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

-	`import org.greenrobot.greendao.annotation.Convert`
-	`import org.greenrobot.greendao.annotation.Entity`
-	`import org.greenrobot.greendao.annotation.Generated`
-	`import org.greenrobot.greendao.annotation.Id`
-	`import org.greenrobot.greendao.annotation.Index`
-	`import org.greenrobot.greendao.annotation.NotNull`
-	`import org.greenrobot.greendao.annotation.*`
-	`import org.greenrobot.greendao.database.Database`
-	`import org.greenrobot.greendao.query.Query`

**`ActiveAndroid`** Search the source code for the following keywords:

-	`ActiveAndroid.initialize(<contextReference>);`
-	`import com.activeandroid.Configuration`
-	`import com.activeandroid.query.*`

**`Realm`** Search the source code for the following keywords:

-	`import io.realm.RealmObject;`
-	`import io.realm.annotations.PrimaryKey;`

##### Parcelable

Verify that, when sensitive information is stored in an Intent using a Bundle containing a Parcelable, the appropriate security measures are taken. Make sure to use explicit intents and reassure proper additional security controls in case of application level IPC (e.g. signature verification, intent-permissions, crypto).

#### Dynamic Analysis

There are various steps one can take for dynamic analysis:

1.	Regarding the actual persistence: use the techniques described in the data storage chapter.
2.	Regarding the reflection based approaches: use Xposed to hook into the de-serialization methods or add extra unprocessable information to the serialized objects to see how they are handled (e.g. Will the application crash? Or can you extract extra information by enriching the objects?).

### References

#### OWASP Mobile Top 10 2016

-	M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."
- V6.4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."
- V6.5: "JavaScript is disabled in WebViews unless explicitly required."
- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."
- V6.7: "If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package."
- V6.8: "Object serialization, if any, is implemented using safe serialization APIs."

#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-749 - Exposed Dangerous Method or Function

#### Tools

- Drozer - https://github.com/mwrlabs/drozer


