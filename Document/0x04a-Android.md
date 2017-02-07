## Android

(... TODO ...)

Android Security Mechanisms:

-- TODO :Sandbox (Dalvik / ART according to API level), IPC mechanism and Reference monitor, Binder, Discretionary - Mandatory Access Control / UID - GID / Filesystem, Applicative Architecture of an application : Permissions & Manifest, Application Signing. May be a part of Static / Dynamic Analysis chapter : each security mechanism efficiency can be checked at a given phase. --

Android is an open source platform that can be found nowadays on many devices:

* Mobile Phones and Tablets
* Wearables
* "Smart" devices in general like TVs

It also offers an application environment that supports not only pre-installed applications on the device, but also 3rd party applications that can be downloaded from marketplaces like Google Play.

The software stack of Android comprises of different layers, where each layer is defining certain behavior and offering specific services to the layer above.

![Android Software Stack](https://source.android.com/security/images/android_software_stack.png)

On the lowest level Android is using the Linux Kernel where the core operating system is built up on. The hardware abstraction layer defines a standard interface for hardware vendors. HAL implementations are packaged into shared library modules (.so files). These modules will be loaded by the Android system at the appropriate time. The Android Runtime consists of the core libraries and the Dalvik VM (Virtual Machine). Applications are most often implemented in Java and compiled in Java class files and then compiled again into the dex format. The dex files are then executed within the Dalvik VM.
In the next image we can see the differences between the normal process of compiling and running a typical project in Java vs the process in Android using Dalvik VM.

![Java vs Dalvik](/Document/images/Chapters/0x04a/java_vs_dalvik.png)

With Android 4.4 the successor of Dalvik VM was introduced, called Android Runtime (ART).

TODO: Explain the differences between ART and Dalvik.

#### UID/GID of Normal Applications

When a new application gets installed on Android a new UID is assigned to it. Generally apps are assigned UIDs in the range of 10000 (_AID_APP_) and 99999. Android apps also receive a user name based on its UID. As an example, application with UID 10188 receives the user name _u0_a188_. 
If an app requested some permissions and they are granted, the corresponding group ID is added to the process of the application.
For example, the user ID of the application below is 10188, and it also belongs to group ID 3003 (_inet_) that is the group related to _android.permission.INTERNET_ permission. The result of the `id` command is shown below:
```
$ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),9997(everybody),50188(all_a188) context=u:r:untrusted_app:s0:c512,c768
```

The relationship between group IDs and permissions are defined in the file [frameworks/base/data/etc/platform.xml](http://androidxref.com/7.1.1_r6/xref/frameworks/base/data/etc/platform.xml)
```
<permission name="android.permission.INTERNET" >
	<group gid="inet" />
</permission>

<permission name="android.permission.READ_LOGS" >
	<group gid="log" />
</permission>

<permission name="android.permission.WRITE_MEDIA_STORAGE" >
	<group gid="media_rw" />
	<group gid="sdcard_rw" />
</permission>
```
#### Application Data Sandbox

Applications are executed in the Android Application Sandbox that enforces isolation of application data and code execution from other applications on the device, that adds an additional layer of security.

When installing new applications (From Google Play or External Sources), a new folder is created in the filesystem in the path /data/data/\<package name>. This folder is going to be the private data folder for that particular application.

Since every application has its own unique Id, Android separates application data folders configuring the mode to _read_ and _write_ only to the owner of the application. 

![Sandbox](/Document/images/Chapters/0x04a/Selection_003.png)

In this example, the Chrome and Calendar app are completly segmented with different UID and different folder permissions.

We can confirm this my looking at the filesystem permissions created for each folder:
```
drwx------  4 u0_a97              u0_a97              4096 2017-01-18 14:27 com.android.calendar
drwx------  6 u0_a120             u0_a120             4096 2017-01-19 12:54 com.android.chrome
```
However, if two applications are signed with the same certificate and explicitly share the same user ID (by including the _sharedUserId_ in their _AndroidManifest.xml_) they can access each other data directory.
An example how this is achieved in Nfc application:
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
	package="com.android.nfc"
	android:sharedUserId="android.uid.nfc">
```



The Android Framework is creating an abstraction layer for all the layers below, so developers can implement Android Apps and can utilize the capabilities of Android without deeper knowledge of the layers below. It also offers a robust implementation that offers common security functions like secure IPC or cryptography.

### Components

Android Applications are composed by several components:

#### Intents

An *Intent* is a messaging object that can be used to request an action from another app component.

#### Activities

Activities are the visible components of any application. They are the application GUI, that allow the user to interact with it.

.....

#### Fragments

A Fragment represents a behavior or a portion of user interface in an Activity.

#### Broadcast Receivers

Broadcast Receivers are components that allow to receive notifications sent from other applications and from the system itself.

....

#### Content Providers

Content Providers are components that create an abstraction layer to allow an application to share their data with other applications (Can be used only for the application itself, without being shared to other applications). 

....

#### Services

Services are components that will perform tasks in the background, without presenting any kind of user interface.

....

### Inter-Process Communication

As we know, every process on Android has its own sandboxed address space. Inter-process communication (IPC) facilities enable apps to exchange signals and data in a (hopefully) secure way. Instead of relying on the default Linux IPC facilities, IPC on Android is done through Binder, a custom implementation of OpenBinder. A lot of Android system services, as well as all high-level IPC services, depend on Binder.

In the Binder framework, a client-server communication model is used. IPC clients communicate through a client-side proxy. This proxy connects to the Binder server, which is implemented as a character driver (/dev/binder).The server holds a thread pool for handling incoming requests, and is responsible for delivering messages to the destination object. Developers  write interfaces for remote services using the Android Interface Descriptor Language (AIDL).

![Binder Overview](/Document/Images/Chapters/0x04a/binder.jpg)
*Binder Overview. Image source: [Android Binder by Thorsten Schreiber](https://www.nds.rub.de/media/attachments/files/2011/10/main.pdf)*

#### High-Level Abstractions

*Intent messaging* is a framework for asynchronous communication built on top of binder. This framework enables both point-to-point and publish-subscribe messaging. An *Intent* is a messaging object that can be used to request an action from another app component. Although intents facilitate communication between components in several ways, there are three fundamental use cases:

- Starting an activity
	- An Activity represents a single screen in an app. You can start a new instance of an Activity by passing an Intent to startActivity(). The Intent describes the activity to start and carries any necessary data.
- Starting an Service
	- A Service is a component that performs operations in the background without a user interface. With Android 5.0 (API level 21) and later, you can start a service with JobScheduler. 
- Delivering a broadcast
	- A broadcast is a message that any app can receive. The system delivers various broadcasts for system events, such as when the system boots up or the device starts charging. You can deliver a broadcast to other apps by passing an Intent to sendBroadcast() or sendOrderedBroadcast().

There are two types of Intents:

- Explicit intents specify the component to start by name (the fully-qualified class name).

- Implicit intents do not name a specific component, but instead declare a general action to perform, which allows a component from another app to handle it. When you create an implicit intent, the Android system finds the appropriate component to start by comparing the contents of the intent to the intent filters declared in the manifest file of other apps on the device.

An *intent filter* is an expression in an app's manifest file that specifies the type of intents that the component would like to receive. For instance, by declaring an intent filter for an activity, you make it possible for other apps to directly start your activity with a certain kind of intent. Likewise, if you do not declare any intent filters for an activity, then it can be started only with an explicit intent.

For activities and broadcast receivers, intents are the preferred mechanism for asynchronous IPC in Android. Depending on your application requirements, you might use sendBroadcast(), sendOrderedBroadcast(), or an explicit intent to a specific application component.

A BroadcastReceiver handles asynchronous requests initiated by an Intent.

Using Binder or Messenger is the preferred mechanism for RPC-style IPC in Android. They provide a well-defined interface that enables mutual authentication of the endpoints, if required.


(... TODO ... briefly on security implications)

Android’s Messenger represents a reference to a Handler that can be sent to a remote process via an Intent

A reference to the Messenger can be sent via an Intent using the previously mentioned IPC mechanism

Messages sent by the remote process via the messenger are delivered to the local handler. Great for efficient call-backs from the service to the client

#### Security Implications



### Android Application Overview

#### App Folder Structure

Android applications installed (from Google Play Store or from external sources) are located at /data/app/. Since this folder cannot be listed without root, another way has to be used to get the exact name of the apk. To list all installed apks, the Android Debug Bridge (adb) can be used. ADB allows a tester to directly interact with the real phone, e.g., to gain access to a console on the device to issue further commands, list installed packages, start/stop processes, etc.
To do so, the device has to have USB-Debugging enabled (under developer settings) and has to be connected via USB.
Once USB-Debugging is enabled, the connected devices can be viewed with the command

```bash
$ adb devices
List of devices attached
BAZ5ORFARKOZYDFA	device
```

Then the following command lists all installed apps and their locations:

```bash
$ adb shell pm list packages -f
package:/system/priv-app/MiuiGallery/MiuiGallery.apk=com.miui.gallery
package:/system/priv-app/Calendar/Calendar.apk=com.android.calendar
package:/system/priv-app/BackupRestoreConfirmation/BackupRestoreConfirmation.apk=com.android.backupconfirm
```

To pull one of those apps from the phone, the following command can be used:

```bash
$ adb pull /data/app/com.google.android.youtube-1/base.apk
```

This file only contains the “installer” of the application, meaning this is the app the developer uploaded to the market.
The local data of the application is stored at /data/data/PACKAGE-NAME and has the following structure:

```bash
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:26 cache
drwx------ u0_a65   u0_a65            2016-01-06 03:26 code_cache
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:31 databases
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 files
drwxr-xr-x system   system            2016-01-06 03:26 lib
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 shared_prefs
```

* **cache**: This location used to cache application data on runtime including WebView caches.
* **code_cache**: TBD
* **databases**: This folder stores sqlite database files generated by the application at runtime, e.g. to store user data
* **files**: This folder is used to store files that are created in the App when using the internal storage.
* **lib**: This folder used to store native libraries written in C/C++. These libraries can have file extension as .so, .dll (x86 support). The folder contains subfolders for the platforms the app has native libraries for:
   * armeabi: compiled code for all ARM based processors only
   * armeabi-v7a: compiled code for all ARMv7 and above based processors only
   * arm64-v8a: compiled code for all ARMv8 arm64 and above based processors only
   * x86: compiled code for x86 processors only
   * x86_64: compiled code for x86_64 processors only
   * mips: compiled code for MIPS processors only
* **shared_prefs**: This folder is used to store the preference file generated by application on runtime to save current state of application including data, configuration, session, etc. The file format is XML.

#### APK Structure

An application on Android is a file with the extension .apk. This file is a signed zip-file which contains different files for the bytecode, assets, etc. When unzipped the following directory structure can be identified:

```bash
$ unzip base.apk
$ ls -lah
-rw-r--r--   1 sven  staff    11K Dec  5 14:45 AndroidManifest.xml
drwxr-xr-x   5 sven  staff   170B Dec  5 16:18 META-INF
drwxr-xr-x   6 sven  staff   204B Dec  5 16:17 assets
-rw-r--r--   1 sven  staff   3.5M Dec  5 14:41 classes.dex
drwxr-xr-x   3 sven  staff   102B Dec  5 16:18 lib
drwxr-xr-x  27 sven  staff   918B Dec  5 16:17 res
-rw-r--r--   1 sven  staff   241K Dec  5 14:45 resources.arsc
```

* **AndroidManifest.xml**: Contains the definition of application’s package name, target and min API version, application configuration, application components, user-granted permissions, etc.
* **META-INF**: This folder contains metadata of application:
   * MANIFEST.MF: stores hashes of application resources.
   * CERT.RSA: The certificate(s) of the application.
   * CERT.SF: The list of resources and SHA-1 digest of the corresponding lines in the MANIFEST.MF file.
* **assets**: A directory containing applications assets (files used within the Android App like XML, Java Script or pictures) which can be retrieved by the AssetManager.
* **classes.dex**: The classes compiled in the DEX file format understandable by the Dalvik virtual machine/Android Runtime. DEX is Java Byte Code for Dalvik Virtual Machine. It is optimized for running on small devices.
* **lib**: A directory containting libraries that are part of the APK, for example 3rd party libraries that are not part of the Android SDK.
* **res**: A directory containing resources not compiled into resources.arsc.
* **resources.arsc**: A file containing precompiled resources, such as XML files for the layout.

Since some resources inside the APK are compressed using non-standard algorithms (e.g. the AndroidManifest.xml), simply unzipping the file does not reveal all information. A better way is to use the tool apktool to unpack and uncompress the files. The following is a listing of the the files contained in the apk:

```bash
$ apktool d base.apk
I: Using Apktool 2.1.0 on base.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /Users/sven/Library/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
$ cd base
$ ls -alh
total 32
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 .
drwxr-xr-x    5 sven  staff   170B Dec  5 16:29 ..
-rw-r--r--    1 sven  staff    10K Dec  5 16:29 AndroidManifest.xml
-rw-r--r--    1 sven  staff   401B Dec  5 16:29 apktool.yml
drwxr-xr-x    6 sven  staff   204B Dec  5 16:29 assets
drwxr-xr-x    3 sven  staff   102B Dec  5 16:29 lib
drwxr-xr-x    4 sven  staff   136B Dec  5 16:29 original
drwxr-xr-x  131 sven  staff   4.3K Dec  5 16:29 res
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 smali
```

* **AndroidManifest.xml**: This file is not compressed anymore and can be openend in a text editor.
* **apktool.yml** : This file contains information about the output of apktool.
* **assets**: A directory containing applications assets (files used within the Android App like XML, Java Script or pictures) which can be retrieved by the AssetManager.
* **lib**: A directory containting libraries that are part of the APK, for example 3rd party libraries that are not part of the Android SDK.
* **original**: This folder contains the MANIFEST.MF file which stores meta data about the contents of the JAR and signature of the APK. The folder can be name as META-INF too.
* **res**: A directory containing resources not compiled into resources.arsc.
* **smali**: A directory containing the disassembled Dalvik Bytecode in Smali. Smali is a human readable representation of the Dalvik executable.


### Android Users and Groups

Android is a system based on Linux, however it does not deal with users the same way Linux does. It does not have a _/etc/password_ file describing a list of Linux users in the system. Instead Android contains a fixed set of users and groups and they are used to isolate processes and grant permissions.
File [system/core/include/private/android_filesystem_config.h](http://androidxref.com/7.1.1_r6/xref/system/core/include/private/android_filesystem_config.h) shows the complete list of the predefined users and groups mapped to numbers.
File below depicts some of the users defined for Android Nougat:
```
    #define AID_ROOT             0  /* traditional unix root user */

    #define AID_SYSTEM        1000  /* system server */
	...
    #define AID_SHELL         2000  /* adb and debug shell user */
	...
    #define AID_APP          10000  /* first app user */
	...
```



### References

+ [Android Security](https://source.android.com/security/)
+ [Android Developer: App Components](https://developer.android.com/guide/components/index.html)
+ [HAL](https://source.android.com/devices/)
+ "Android Security: Attacks and Defenses" By Anmol Misra, Abhishek Dubey
+ [AProgrammer Blog](https://pierrchen.blogspot.com.br)
+ [keesj Android internals](https://github.com/keesj/gomo)
