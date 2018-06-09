## Android Platform Overview

This section introduces the Android platform from the architecture point of view. The following four key areas are discussed:

1. Android security architecture
2. Android application structure
3. Inter-process Communication (IPC)
4. Android application publishing

Visit the official [Android developer documentation website](https://developer.android.com/index.html "Android Developer Guide") for more details about the Android platform.

### Android Security Architecture

Android is a Linux-based open source platform developed by Google as a mobile operating system (OS). Today the platform is the foundation for a wide variety of modern technology, such as mobile phones, tablets, wearable tech, TVs, and other "smart" devices. Typical Android builds ship with a range of pre-installed ("stock") apps and support installation of third-party apps through the Google Play store and other marketplaces.

Android's software stack is composed of several different layers. Each layer defines interfaces and offers specific services.

![Android Software Stack](Images/Chapters/0x05a/android_software_stack.png)

At the lowest level, Android is based on a variation of the Linux Kernel. On top of the kernel, the Hardware Abstraction Layer (HAL) defines a standard interface for interacting with built-in hardware components. Several HAL implementations are packaged into shared library modules that the Android system calls when required. This is the basis for allowing applications to interact with the device's hardware—for example, it allows a stock phone application to use a device's microphone and speaker.

Android apps are usually written in Java and compiled to Dalvik bytecode, which is somewhat  different from the traditional Java bytecode. Dalvik bytecode is created by first compiling the Java code to .class files, then converting the JVM bytecode to the Dalvik .dex format with the `dx` tool.

![Java vs Dalvik](Images/Chapters/0x05a/java_vs_dalvik.png)

The current version of Android executes this bytecode on the Android runtime (ART). ART is the successor to Android's original runtime, the Dalvik Virtual Machine. The key difference between Dalvik and ART is the way the bytecode is executed.

In Dalvik, bytecode is translated into machine code at execution time, a process known as *just-in-time* (JIT) compilation. JIT compilation adversely affects performance: the compilation must be performed every time the app is executed. To improve performance, ART introduced *ahead-of-time* (AOT) compilation. As the name implies, apps are precompiled before they are executed for the first time. This precompiled machine code is used for all subsequent executions. AOT improves performance by a factor of two while reducing power consumption.

Android apps don't have direct access to hardware resources, and each app runs in its own sandbox. This allows precise control over resources and apps: for instance, a crashing app doesn't affect other apps running on the device. At the same time, the Android runtime controls the maximum number of system resources allocated to apps, preventing any one app from monopolizing too many resources.

#### Android Users and Groups

Even though the Android operating system is based on Linux, it doesn't implement user accounts in the same way other Unix-like systems do. In Android, the multi-user support of the Linux kernel to sandbox apps: with a few exceptions, each app runs as though under a separate Linux user, effectively isolated from other apps and the rest of the operating system.

The file [system/core/include/private/android_filesystem_config.h](http://androidxref.com/7.1.1_r6/xref/system/core/include/private/android_filesystem_config.h) includes a list of the predefined users and groups  system processes are assigned to. UIDs (userIDs) for other applications are added as the latter are installed. For more details, check out Bin Chen's [blog post](https://pierrchen.blogspot.mk/2016/09/an-walk-through-of-android-uidgid-based.html "Bin Chen - AProgrammer Blog - Android Security: An Overview Of Application Sandbox") on Android sandboxing.

For example, Android Nougat defines the following system users:

```
    #define AID_ROOT             0  /* traditional unix root user */

    #define AID_SYSTEM        1000  /* system server */
	...
    #define AID_SHELL         2000  /* adb and debug shell user */
	...
    #define AID_APP          10000  /* first app user */
	...
```

### Android Application Structure

#### Communication with the Operating System

Android apps interact with system services via the Android Framework, an abstraction layer that offers high-level Java APIs. The majority of these services are invoked via normal Java method calls and are translated to IPC calls to system services that are running in the background. Examples of system services include:

    - Connectivity (Wi-Fi, Bluetooth, NFC, etc.)
    - Giles
    - Cameras
    - Geolocation (GPS)
    - Microphone

The framework also offers common security functions, such as cryptography.

The API specifications change with every new Android release. Critical bug fixes and security patches are usually applied to earlier versions as well. The oldest Android version supported at the time of writing is 4.4 (KitKat), API level 19, and the current Android version is 7.1 (Nougat), API level 25.

Noteworthy API versions:

- Android 4.2 Jelly Bean (API 16) in November 2012 (introduction of SELinux)
- Android 4.3 Jelly Bean (API 18) in July 2013 (SELinux became enabled by default)
- Android 4.4 KitKat (API 19) in October 2013 (several new APIs and ART introduced)
- Android 5.0 Lollipop (API 21) in November 2014 (ART used by default and many other features added)
- Android 6.0 Marshmallow (API 23) in October 2015 (many new features and improvements, including granting; detailed permissions setup at run time rather than all or nothing during installation)
- Android 7.0 Nougat (API 24-25) in August 2016 (new JIT compiler on ART)
- Android 8.0 O (API 26) beta (major security fixes expected)

#### App Folder Structure

Installed Android apps are located at `/data/app/[package-name]`. For example, the YouTube app is located at:

```bash
/data/app/com.google.android.youtube-1/base.apk
```

The Android Package Kit (APK) file is an archive that contains the code and resources required to run the app it comes with. This file is identical to the original, signed app package created by the developer. It is in fact a ZIP archive with the following directory structure:

```
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

- AndroidManifest.xml: contains the definition of the app's package name, target and min API version, app configuration, components, user-granted permissions, etc.
- META-INF: contains the app's metadata
  - MANIFEST.MF: stores hashes of the app resources
  - CERT.RSA: the app's certificate(s)
  - CERT.SF: list of resources and the SHA-1 digest of the corresponding lines in the MANIFEST.MF file
- assets: directory containing app assets (files used within the Android app, such as XML files, JavaScript files, and pictures), which the AssetManager can retrieve
- classes.dex: classes compiled in the DEX file format, the Dalvik virtual machine/Android Runtime can process. DEX is Java bytecode for the Dalvik Virtual Machine. It is optimized for small devices
- lib: directory containing libraries that are part of the APK, for example, the third-party libraries that aren't part of the Android SDK
- res: directory containing resources that haven't been compiled into resources.arsc
- resources.arsc: file containing precompiled resources, such as XML files for the layout

Note that unzipping with the standard `unzip` utility the archive leaves some files unreadable. `AndroidManifest.XML` is encoded into binary XML format which isn’t readable with a text editor. Also, the app resources are still packaged into a single archive file.
A better way of unpacking an Android app package is using [apktool](https://ibotpeaches.github.io/Apktool/). When run with default command line flags, apktool automatically decodes the Manifest file to text-based XML format and extracts the file resources (it also disassembles the .DEX files to Smali code – a feature that we’ll revisit later in this book).

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

- AndroidManifest.xml: The decoded Manifest file, which can be opened and edited in a text editor.
- apktool.yml: file containing information about the output of apktool
- original: folder containing the MANIFEST.MF file, which contains information about the files contained in the JAR file
- res: directory containing the app’s resources
- smali: directory containing the disassembled Dalvik bytecode in Smali. Smali is a human-readable representation of the Dalvik executable.
Every app also has a data directory for storing data created during run time. This directory is at `/data/data/[package-name]` and has the following structure:

```bash
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:26 cache
drwx------ u0_a65   u0_a65            2016-01-06 03:26 code_cache
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:31 databases
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 files
drwxr-xr-x system   system            2016-01-06 03:26 lib
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 shared_prefs
```

- **cache**: This location is used for data caching. For example, the WebView cache is found in this directory.
- **code_cache**: This is the location of the file system's application-specific cache directory designed for storing cached code. On devices running Lollipop or later Android versions, the system will delete any files stored in this location when the app or the entire platform is upgraded.
- **databases**: This folder stores SQLite database files generated by the app at run time, e.g., user data files.
- **files**: This folder stores regular files created by the app.
- **lib**: This folder stores native libraries written in C/C++. These libraries can have one of several file extensions, including .so and .dll (x86 support). This folder contains subfolders for the platforms the app has native libraries for, including
   * armeabi: compiled code for all ARM-based processors
   * armeabi-v7a: compiled code for all ARM-based processors, version 7 and above only
   * arm64-v8a: compiled code for all 64-bit ARM-based processors, version 8 and above based only
   * x86: compiled code for x86 processors only
   * x86_64: compiled code for x86_64 processors only
   * mips: compiled code for MIPS processors
- **shared_prefs**: This folder contains an XML file that stores values saved via the [SharedPreferences APIs]( https://developer.android.com/training/basics/data-storage/shared-preferences.html).

#### Linux UID/GID for Normal Applications

Android leverages Linux user management to isolate apps. This approach is different from user management usage in traditional Linux environments, where multiple apps are often run by the same user. Android creates a unique UID for each Android app and runs the app in a separate process. Consequently, each app can access its own resources only. This protection is enforced by the Linux kernel.

Generally, apps are assigned UIDs in the range of 10000 and 99999. Android apps receive a user name based on their UID. For example, the app with UID 10188 receives the user name `u0_a188`. If the permissions an app requested are granted, the corresponding group ID is added to the app's process. For example, the user ID of the app below is 10188. It belongs to the group ID 3003 (inet). That group is related to android.permission.INTERNET permission. The output of the `id` command is shown below.
```
$ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),9997(everybody),50188(all_a188) context=u:r:untrusted_app:s0:c512,c768
```

The relationship between group IDs and permissions is defined in the file [frameworks/base/data/etc/platform.xml](http://androidxref.com/7.1.1_r6/xref/frameworks/base/data/etc/platform.xml)
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

#### The App Sandbox

Apps are executed in the Android Application Sandbox, which separates the app data and code execution from other apps on the device. This separation adds a layer of security.

Installation of a new app creates a new directory named after the app package— `/data/data/[package-name]`. This directory holds the app's data. Linux directory permissions are set such that the directory can be read from and written to only with the app's unique UID.

![Sandbox](Images/Chapters/0x05a/Selection_003.png)

We can confirm this by looking at the file system permissions in the `/data/data` folder. For example, we can see that Google Chrome and Calendar are assigned one directory each and run under different user accounts:

```
drwx------  4 u0_a97              u0_a97              4096 2017-01-18 14:27 com.android.calendar
drwx------  6 u0_a120             u0_a120             4096 2017-01-19 12:54 com.android.chrome
```

Developers who want their apps to share a common sandbox can sidestep sandboxing . When two apps are signed with the same certificate and explicitly share the same user ID (having the _sharedUserId_ in their _AndroidManifest.xml_ files), each can access the other's data directory. See the following example to achieve this in the NFC app:

```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.android.nfc"
  android:sharedUserId="android.uid.nfc">
```

##### Zygote

The process `Zygote` starts up during [Android initialization](https://github.com/dogriffiths/HeadFirstAndroid/wiki/How-Android-Apps-are-Built-and-Run "How Android Apps are run"). Zygote is a system service for launching apps. The Zygote process is a "base" process that contains all the core libraries the app needs. Upon launch, Zygote opens the socket ` /dev/socket/zygote` and listens for connections from local clients. When it receives a connection, it forks a new process, which then loads and executes the app-specific code.

##### App Lifecycle

In Android, the lifetime of an app process is controlled by the operating system. A new Linux process is created when an app component is started and the same app doesn’t yet have any other components running. Android may kill this process when the latter is no longer necessary or when reclaiming memory is necessary to run more important apps. The decision to kill a process is primarily related to the state of the user's interaction with the process. In general, processes can be in one of four states.

- A foreground process (e.g., an activity running at the top of the screen or a running BroadcastReceive)
- A visible process is a process that the user is aware of, so killing it would have a noticeable negative impact on user experience. One example is running an activity that's visible to the user on-screen but not in the foreground.

- A service process is a process hosting a service that has been started with the `startService` method. Though these processes aren't directly visible to the user, they are generally things that the user cares about (such as background network data upload or download), so the system will always keep such processes running unless there's insufficient memory to retain all foreground and visible processes.
- A cached process is a process that's not currently needed, so the system is free to kill it when memory is needed.
Apps must implement callback methods that react to a number of events; for example, the `onCreate` handler is called when the app process is first created. Other callback methods include `onLowMemory`, `onTrimMemory` and `onConfigurationChanged`.

##### Manifest

Every app has a manifest file, which embeds content in binary XML format. The standard name of this file is AndroidManifest.xml. It is located in the root directory of the app’s APK file.

The manifest file describes the app structure, its components (activities, services, content providers, and intent receivers), and requested permissions. It also contains general app metadata, such as the app's  icon, version number, and theme. The file may list other information,  such as compatible APIs (minimal, targeted, and maximal SDK version) and the [kind of storage it can be installed on (external or internal)](https://developer.android.com/guide/topics/data/install-location.html "Define app install location").

Here is an example of a manifest file, including the package name (the convention is a reversed  URL, but any string is acceptable). It also lists the app version, relevant SDKs, required permissions, exposed content providers, broadcast receivers used with intent filters, and a description of the app and its activities:
```
<manifest
	package="com.owasp.myapplication"
	android:versionCode="0.1" >

	<uses-sdk android:minSdkVersion="12"
		android:targetSdkVersion="22"
		android:maxSdkVersion="25" />

	<uses-permission android:name="android.permission.INTERNET" />

	<provider
		android:name="com.owasp.myapplication.myProvider"
		android:exported="false" />

	<receiver android:name=".myReceiver" >
		<intent-filter>
			<action android:name="com.owasp.myapplication.myaction" />
		</intent-filter>
	</receiver>

	<application
		android:icon="@drawable/ic_launcher"
		android:label="@string/app_name"
		android:theme="@style/Theme.Material.Light" >
		<activity
			android:name="com.owasp.myapplication.MainActivity" >
			<intent-filter>
				<action android:name="android.intent.action.MAIN" />
			</intent-filter>
		</activity>
	</application>
</manifest>
```

The full list of available manifest options is in the official [Android Manifest file documentation](https://developer.android.com/guide/topics/manifest/manifest-intro.html "Android Developer Guide for Manifest").

#### App Components

Android apps are made of several high-level components. The main components are:

- Activities
- Fragments
- Intents
- Broadcast receivers
- Content providers and services

All these elements are provided by the Android operating system, in the form of predefined classes available through APIs.

##### Activities

Activities make up the visible part of any app. There is one activity per screen, so an app with three different screens implements three different activities. Activities are declared by extending the Activity class. They contain all user interface elements: fragments, views, and layouts.

Each activity needs to be declared in the app manifest with the following syntax:

```
<activity android:name="ActivityName">
</activity>
```

Activities not declared in the manifest can't be displayed, and attempting to launch them will raise an exception.

Like apps, activities have their own lifecycle and need to monitor system changes to handle them. Activities can be in the following states: active, paused, stopped, and inactive. These states are managed by the Android operating system. Accordingly, activities can implement the following event managers:

- onCreate
- onSaveInstanceState
- onStart
- onResume
- onRestoreInstanceState
- onPause
- onStop
- onRestart
- onDestroy

An app may not explicitly implement all event managers, in which case default actions are taken. Typically, at least the `onCreate` manager is overridden by the app developers. This is how most user interface components are declared and initialized. `onDestroy` may be overridden when resources (like network connections or connections to databases) must be explicitly released or specific actions must occur when the app shuts down.

##### Fragments

A fragment represents a behavior or a portion of the user interface within the activity. Fragments were introduced Android with the version Honeycomb 3.0 (API level 11).

Fragments are meant to encapsulate parts of the interface to facilitate re-usability and adaptation to different screen sizes. Fragments are autonomous entities in that they include all their required components (they have their own layout, buttons, etc.). However, they must be integrated with activities to be useful: fragments can't exist on their own. They have their own lifecycle, which is tied to the lifecycles of the Activities that implement them.

Because fragments have their own lifecycle, the Fragment class contains event managers that can be redefined and extended. These event managers included onAttach, onCreate, onStart, onDestroy and onDetach. Several others exist; the reader should refer to the [Android Fragment specification](https://developer.android.com/reference/android/app/Fragment.html "Fragment Class") for more details.

Fragments can be easily implemented by extending the Fragment class provided by Android:

```Java
public class myFragment extends Fragment {
	...
}
```

Fragments don't need to be declared in manifest files because they depend on activities.

To manage its fragments, an activity can use a Fragment Manager (FragmentManager class). This class makes it easy to find, add, remove, and replace associated fragments.

Fragment Managers can be created via the following:

```Java
FragmentManager fm = getFragmentManager();
```

Fragments don't necessarily have a user interface; they can be a convenient and efficient way to manage background operations pertaining to the app's user interface. A fragment may be declared persistent so that it the system preserves its state even if its Activity is destroyed.

##### Inter-Process Communication

As we've already learned, every Android process has its own sandboxed address space. Inter-process communication facilities allow apps to exchange signals and data securely. Instead of relying on the default Linux IPC facilities, Android's IPC is based on Binder, a custom implementation of OpenBinder. Most Android system services and all high-level IPC services depend on Binder.

The term *Binder* stands for a lot of different things, including:

- Binder Driver: the kernel-level driver
- Binder Protocol: low-level ioctl-based protocol used to communicate with the binder driver
- IBinder Interface: a well-defined behavior that Binder objects implement
- Binder object: generic implementation of the IBinder interface
- Binder service: implementation of the Binder object; for example, location service, and sensor service
- Binder client: an object using the Binder service

The Binder framework includes a client-server communication model. To use IPC, apps call IPC methods in proxy objects. The proxy objects transparently *marshall* the call parameters into a *parcel* and send a transaction to the Binder server, which is implemented as a character driver (/dev/binder). The server holds a thread pool for handling incoming requests and delivers messages to the destination object. From the perspective of the client app, all of this seems like a regular method call—all the heavy lifting is done by the Binder framework.

![Binder Overview](Images/Chapters/0x05a/binder.jpg)
*Binder Overview. Image source: [Android Binder by Thorsten Schreiber](https://www.nds.rub.de/media/attachments/files/2011/10/main.pdf)*

Services that allow other applications to bind to them are called *bound services*. These services must provide an IBinder interface to clients. Developers use the Android Interface Descriptor Language (AIDL) to write interfaces for remote services.

Servicemanager is a system daemon that manages the registration and lookup of system services. It maintains a list of name/Binder pairs for all registered services. Services are added with `addService` and retrieved by name with the static `getService` method in `android.os.ServiceManager`:

```
  public static IBinder getService(String name)
```

You can query the list of system services with the `service list` command.


```
$ adb shell service list
Found 99 services:
0 carrier_config: [com.android.internal.telephony.ICarrierConfigLoader]
1 phone: [com.android.internal.telephony.ITelephony]
2 isms: [com.android.internal.telephony.ISms]
3 iphonesubinfo: [com.android.internal.telephony.IPhoneSubInfo]
```

#### Intents

*Intent messaging* is an asynchronous communication framework built on top of Binder. This framework allows both point-to-point and publish-subscribe messaging. An *Intent* is a messaging object that can be used to request an action from another app component. Although intents facilitate inter-component communication in several ways, there are three fundamental use cases:

- Starting an activity
    - An activity represents a single screen in an app. You can start a new instance of an activity by passing an intent to `startActivity`. The intent describes the activity and carries necessary data.
- Starting a service
    - A Service is a component that performs operations in the background, without a user interface. With Android 5.0 (API level 21) and later, you can start a service with JobScheduler.
- Delivering a broadcast
    - A broadcast is a message that any app can receive. The system delivers broadcasts for system events, including system boot and charging initialization. You can deliver a broadcast to other apps by passing an intent to `sendBroadcast` or `sendOrderedBroadcast`.

Intents are components for sending messages between apps and components. An app can use them to send information to its own components (for instance, to start a new activity inside the app), to other apps, or to the operating system. Intents can be used to start Activities and services, run actions on given data, and broadcast messages to the whole system.

There are two types of intents. Explicit intents name the component that will be started (the fully qualified class name). For instance:

```Java
    Intent intent = new Intent(this, myActivity.myClass);
```

Implicit intents are sent to the OS to perform a given action on a given set of data ("http://www.example.com" in our example below). It is up to the system to decide which app or class will perform the corresponding service. For instance:

```Java
    Intent intent = new Intent(Intent.MY_ACTION, Uri.parse("http://www.example.com"));
```

An *intent filter* is an expression in app manifest files that specifies the type of intents the component would like to receive. For instance, by declaring an intent filter for an activity, you make it possible for other apps to directly start your activity with a certain kind of intent. Likewise, your activity can only be started with an explicit intent if you don't declare any intent filters for it.

Android uses intents to broadcast messages to apps (such as an incoming call or SMS) important power supply information (low battery, for example), and network changes (loss of connection, for instance). Extra data may be added to intents (through `putExtra`/`getExtras`).

Here is a short list of intents sent by the operating system. All constants are defined in the Intent class, and the whole list is in the official Android documentation:

- ACTION_CAMERA_BUTTON
- ACTION_MEDIA_EJECT
- ACTION_NEW_OUTGOING_CALL
- ACTION_TIMEZONE_CHANGED

To improve security and privacy, a Local Broadcast Manager is used to send and receive intents within an app without having them sent to the rest of the operating system. This is very useful for ensuring that sensitive and private data don't leave the app perimeter (geolocation data for instance).

##### Broadcast Receivers

Broadcast Receivers are components that allow apps to receive notifications from other apps and from the system itself. With it, apps can react to events (internal, initiated by other apps, or initiated by the operating system). They are generally used to update user interfaces, start services, update content, and create user notifications.

Broadcast Receivers must be declared in the app's manifest file. The manifest must specify an association between the Broadcast Receiver and an intent filter to indicate the actions the receiver is meant to listen for. If Broadcast Receivers aren't declared, the app won't listen to broadcasted messages. However, apps don’t need to be running to receive intents; the system starts apps automatically when a relevant intent is raised.

An example Broadcast Receiver declaration with an intent filter in a manifest:
```
	<receiver android:name=".myReceiver" >
		<intent-filter>
			<action android:name="com.owasp.myapplication.MY_ACTION" />
		</intent-filter>
	</receiver>
```

After receiving an implicit intent, Android will list all apps that have registered a given action in their filters. If more than one app has registered for the same action, Android will prompt the user to select from the list of available apps.

An interesting feature of Broadcast Receivers is that they are assigned a priority; this way, an intent will be delivered to all authorized receivers according to their priority.

A Local Broadcast Manager can be used to make sure intents are received from the internal app only, and any intent from any other app will be discarded. This is very useful for improving security.

##### Content Providers

Android uses SQLite to store data permanently: as with Linux, data is stored in files. SQLite is a light, efficient, open source relational data storage technology that does not require much processing power, which makes it ideal for mobile use. An entire API with specific classes (Cursor, ContentValues, SQLiteOpenHelper, ContentProvider, ContentResolver, etc.) is available.
SQLite is not run as a separate process; it is part of the app.
By default, a database belonging to a given app is accessible to this app only. However, content providers offer a great mechanism for abstracting data sources (including databases and flat files); they also provide a standard and efficient mechanism to share data between apps, including native apps. To be accessible to other apps, a content provider needs to be explicitly declared in the manifest file of the app that will share it. As long as content providers aren't declared, they won't be exported and can only be called by the app that creates them.

content providers are implemented through a URI addressing scheme: they all use the content:// model. Regardless of the type of sources (SQLite database, flat file, etc.), the addressing scheme is always the same, thereby abstracting the sources and offering the developer a unique scheme. Content Providers offer all regular database operations: create, read, update, delete. That means that any app with proper rights in its manifest file can manipulate the data from other apps.

##### Services

Services are Android OS components (based on the Service class) that perform tasks in the background (data processing, starting intents, and notifications, etc.) without presenting a user interface. Services are meant to run processes long-term. Their system priorities are lower than those of active apps and higher than those of inactive apps. Therefore, they are less likely to be killed when the system needs resources, and they can be configured to automatically restart when enough resources become available. Activities are executed in the main app thread. They are great candidates for running asynchronous tasks.

##### Permissions

Because Android apps are installed in a sandbox and initially can't access user information and system components (such as the camera and the microphone), Android provides a system with a predefined set of permissions for certain tasks that the app can request.
For example, if you want your app to use a phone's camera, you have to request the ` android.permission.CAMERA ` permission.
Prior to Marshmallow (API 23), all permissions an app requested were granted at installation. From Android Marshmallow onwards, the user must approve some permissions requests during app execution.

###### Protection Levels

Android permissions are ranked on the basis of the protection level they offer and divided into four different categories:
- *Normal*: the lower level of protection. It gives the apps access to isolated application-level features with minimal risk to other apps, the user, or the system. It is granted during app installation and is the default protection level:
Example: `android.permission.INTERNET`
- *Dangerous*: This permission allows the app to perform actions that might affect the user’s privacy or the normal operation of the user’s device. This level of permission may not be granted during installation; the user must decide whether the app should have this permission.
Example: `android.permission.RECORD_AUDIO`
- *Signature*: This permission is granted only if the requesting app has been signed with the same certificate as the app that declared the permission. If the signature matches, the permission is automatically granted.
Example: `android.permission.ACCESS_MOCK_LOCATION`
- *SystemOrSignature*: This permission is granted only to apps embedded in the system image or signed with the same certificate that the app that declared the permission was signed with.
Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`

###### Requesting Permissions

Apps can request permissions for the protection levels Normal, Dangerous, and Signature by including `<uses-permission />` tags  into their manifest.
The example below shows an AndroidManifest.xml sample requesting permission to read SMS messages:
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.permissions.sample" ...>

    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <application>...</application>
</manifest>
```
###### Declaring Permissions

Apps can expose features and content to other apps installed on the system. To restrict access to its own components, it can either use any of Android’s [predefined permissions](https://developer.android.com/reference/android/Manifest.permission.html)  or define its own. A new permission is declared with the <permission>element.
The example below shows an app declaring a permission:
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.permissions.sample" ...>

    <permission
    android:name="com.permissions.sample.ACCESS_USER_INFO"
    android:protectionLevel="signature" />
    <application>...</application>
</manifest>
```
The above code defines a new permission named `com.permissions.sample.ACCESS_USER_INFO` with the protection level `Signature`. Any components protected with this permission would be accessible only by apps signed with the same developer certificate.

###### Enforcing Permissions on Android Components

Android components can be protected with permissions. Activities, Services, Content Providers, and Broadcast Receivers—all can use the permission mechanism to protect their interfaces.
Permissions can be enforced on *Activities*, *Services*, and *Broadcast Receivers* by adding the attribute *android:permission* to the respective component tag in AndroidManifest.xml:
```
<receiver
    android:name="com.permissions.sample.AnalyticsReceiver"
    android:enabled="true"
    android:permission="com.permissions.sample.ACCESS_USER_INFO">
    ...
</receiver>
```
*Content Providers* are a little different. They support a separate set of permissions for reading, writing, and accessing the content provider with a content URI.
- `android:writePermission`, `android:readPermission`: the developer can set separate permissions for reading or writing
- `android:permission`: general permission that will control reading and writing to the content provider
- `android:grantUriPermissions`: true if the content provider can be accessed with a content URI (the access temporarily bypasses the restrictions of other permissions), and false otherwise

### Signing and Publishing Process
Once an app has been successfully developed, the next step is to publish and share it with others. However, apps can't simply be added to a store and shared, for several reasons—they must be signed. The cryptographic signature serves as a verifiable mark placed by the developer of the app. It identifies the app’s author and ensures that the app has not been modified since its initial distribution.
#### Signing Process
During development, apps are signed with an automatically generated certificate. This certificate is inherently insecure and is for debugging only. Most stores don't accept this kind of certificate for publishing; therefore, a certificate with more secure features must be created.
When an application is installed on the Android device, the Package Manager ensures that it has been signed with the certificate included in the corresponding APK. If the certificate's public key matches the key used to sign any other APK on the device, the new APK may share a UID with the pre-existing APK. This facilitates interactions between applications from a single vendor. Alternatively, specifying security permissions for the Signature protection level is possible; this will restrict access to applications that have been signed with the same key.
#### APK Signing Schemes
Android supports two application signing schemes. Starting with Android 7.0, APKs can be verified with the APK Signature Scheme v2 (v2 scheme) or JAR signing (v1 scheme). For backwards compatibility, APKs signed with the v2 signature format can be installed on older Android devices as long as the former are also v1-signed. [Older platforms ignore v2 signatures and verify v1 signatures only](https://source.android.com/security/apksigning/ "APK Signing ").
##### JAR Signing (v1 Scheme)
The original version of app signing implements the signed APK as a standard signed JAR, which must contain all the entries in `META-INF/MANIFEST.MF`. All files must be signed with a common certificate. This scheme does not protect some parts of the APK, such as ZIP metadata. The drawback of this scheme is that the APK verifier needs to process untrusted data structures before applying the signature, and the verifier discards data the data structures don't cover. Also, the APK verifier must decompress all compressed files, which takes considerable time and memory.
##### APK Signature Scheme (v2 Scheme)
With the APK signature scheme, the complete APK is hashed and signed, and an APK Signing Block is created and inserted into the APK. During validation, the v2 scheme checks the signatures of the entire APK file. This form of APK verification is faster and offers more comprehensive protection against modification.

![Preparation](Images/Chapters/0x05a/apk-validation-process.png)
[APK signature verification process](https://source.android.com/security/apksigning/v2#verification "APK Signature verification process")

##### Creating Your Certificate
Android uses public/private certificates to sign Android apps (.apk files). Certificates are bundles of information; in terms of security, keys are the most important type of this information Public certificates contain users' public keys, and private certificates contain users' private keys. Public and private certificates are linked. Certificates are unique and can't be re-generated. Note that if a certificate is lost, it cannot be recovered, so updating any apps signed with that certificate becomes impossible.
App creators can either reuse an existing private/public key pair that is in an available keystore or generate a new pair.
In the Android SDK, a new key pair is generated with the `keytool` command. The following command creates a RSA key pair with a key length of 2048 bits and an expiry time of 7300 days = 20 years. The generated key pair is stored in the file 'myKeyStore.jks', which is in the current directory):
```
keytool -genkey -alias myDomain -keyalg RSA -keysize 2048 -validity 7300 -keystore myKeyStore.jks -storepass myStrongPassword
```

Safely storing your secret key and making sure it remains secret during its entire lifecycle is of paramount importance. Anyone who gains access to the key will be able to publish updates to your apps with content that you don't control (thereby adding insecure features or accessing shared content with signature-based permissions). The trust that a user places in an app and its developers is based totally on such certificates; certificate protection and secure management are therefore vital for reputation and customer retention, and secret keys must never be shared with other individuals. Keys are stored in a binary file that can be protected with a password; such files are referred to as 'keystores'. Keystore passwords should be strong and known only to the key creator. For this reason, keys are usually stored on a dedicated build machine that developers have limited access to.
An Android certificate must have a validity period that's longer than that of the associated app (including updated versions of the app). For example, Google Play will require  certificates to remain valid until Oct 22nd, 2033 at least.
##### Signing an Application
The goal of the signing process is to associate the app file (.apk) with the developer's public key.  To achieve this, the developer calculates a hash of the APK file and encrypts it with their own private key. Third parties can then verify the app's authenticity (e.g., the fact that the app really comes from the user who claims to be the originator) by decrypting the encrypted hash with the author’s public key and verifying that it matches the actual hash of the APK file.

Many Integrated Development Environments (IDE) integrate the app signing process to make it easier for the user. Be aware that some IDEs store private keys in clear text in configuration files; double-check this in case others are able to access such files and remove the information if necessary.
Apps can be signed from the command line with the 'apksigner' tool provided by the Android SDK (API 24 and higher) or the Java JDK tool 'jarsigner' (for earlier Android versions). Details about the whole process can be found in official Android documentation; however, an example is given below to illustrate the point.
```
apksigner sign --out mySignedApp.apk --ks myKeyStore.jks myUnsignedApp.apk
```
In this example, an unsigned app ('myUnsignedApp.apk') will be signed with a private key from the developer keystore 'myKeyStore.jks' (located in the current directory). The app will become a signed app called 'mySignedApp.apk' and will be ready to release to stores.

###### Zipalign

The `zipalign` tool should always be used to align the APK file before distribution. This tool aligns all uncompressed data (such as images, raw files, and 4-byte boundaries) within the APK  that helps improve memory management during app run time. zipalign must be used before the APK file is signed with apksigner.

#### Publishing Process

Distributing apps from anywhere (your own site, any store, etc.) is possible because the Android ecosystem is open. However, Google Play is the most well-known, trusted, and popular store, and Google itself provides it. Amazon Appstore is the trusted default store for Kindle devices. If users want to install third-party apps from a non-trusted source, they must explicitly allow this with their device security settings.

Apps can be installed on an Android device from a variety of sources: locally via USB, via Google's official app store (Google Play Store) or from alternative stores.

Whereas other vendors may review and approve apps before they are actually published, Google will simply scan for known malware signatures; this minimizes the time between the beginning of the publishing process and public app availability.

Publishing an app is quite straightforward; the main operation is making the signed .apk file downloadable. On Google Play, publishing starts with account creation and is followed by app delivery through a dedicated interface. Details are available from the official Android documentation at https://developer.android.com/distribute/googleplay/start.html.
