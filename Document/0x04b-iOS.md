## iOS

### Structure of an iOS Application

iOS applications are distributed in IPA (iOS App Store Package) archives. This IPA file contains all the necessary (for ARM compiled) application code and resources required to execute the application. The container is in fact a ZIP compressed file, which can be easily decompressed.
An IPA has a built-in structure for iTunes and App Store to recognize, The example below shows the high level structure of an IPA. 
* /Payload/ folder contains all the application data. We will come back to the content of this folder in more detail.
* /Payload/Application.app contains the application data itself (ARM compiled code) and associated static resources
* /iTunesArtwork is a 512x512 pixel PNG images used as the application’s icon
* /iTunesMetadata.plist contains various bits of information, ranging from the developer's name and ID, the bundle identifier, copyright information, genre, the name of the app, release date, purchase date, etc.
* /WatchKitSupport/WK is an example of an extension bundle. This specific bundle contains the extension delegate and the controllers for managing the interfaces and for responding to user interactions on an Apple watch.

### Installation of an application

Different methods exist to install an IPA package on the device. The easiest solution is to use iTunes, which is the default media player from Apple. ITunes Packages exist for OS X as well as for Windows. iTunes allows you to download applications through the App Store, after which you can synchronise them to an iOS device. The App store is the official application distribution platform from Apple. You can also use iTunes to load an ipa to a device. This can be done by adding “dragging” it into the Apps section, after which we can then add it to a device. 

On Linux we can make use of libimobiledevice, a cross-platform software protocol library and set of tools to communicate with iOS devices natively. Through ideviceinstaller we can install packages over an USB connection. The connection is implemented using USB multiplexing daemon [usbmuxd] which provides a TCP tunnel over USB. During normal operations, iTunes communicates with the iPhone using this usbmux, multiplexing several “connections” over the one USB pipe. Processes on the host machine open up connections to specific, numbered ports on the mobile device. [usbmux]

On the iOS device, the actual installation process is then handled by installd daemon, which will unpack and install it. Before your app can integrate app services, be installed on a device, or be submitted to the App Store, it must be signed with a certificate issued by Apple. This means that we can only install it after the code signature is valid. On a jailbroken phone this can however be circumvented using [AppSync], a package made available on the Cydia store. This is an alternate app store containing a lot of useful applications which leverage root privileges provided through the jailbreak in order to execute advanced functionalities. AppSync is a tweak that patches installd to allow for the installation of fake-signed IPA packages.

The IPA can also be installed directly from command line by using [ipainstaller]. After copying the IPA onto the device, for example by using scp (secure copy), the ipainstaller can be executed with the filename of the IPA:

```bash
$ ipainstaller App_in_scope.ipa
```

### Application locations

SInce iOS 8, changes were made to the way an application is stored on the device. On versions before iOS 8, applications would be unpacked to a folder in the /var/mobile/applications/ folder. The application would be identified by its UUID (Universal Unique Identifier), a 128-bit number. This would be the name of the folder in which we will find the application itself. Since iOS 8 this has changed however, so we will see that the static bundle and the application data folders are now stored in different locations on the filesystem. These folders contain information that we will need to closely examine during application security assessments.

* /var/mobile/Containers/Bundle/Application/[UUID]/Application.app contains the previously mentioned application.app data and stores the static content as well as the ARM compiled binary of the application. The content of this folder will be used to validate the code signature.
* /var/mobile/Containers/Data/Application/[UUID]/Documents contains all the data stored for the application itself. The creation of this data is initiated by the application’s end user.
* /var/mobile/Containers/Data/Application/[UUID]/Library contains files necessary for the application e.g. caches, preferences, cookies, property list (plist) configuration files, etc. 
* /var/mobile/Containers/Data/Application/[UUID]/Temp contains temporary files which do not need persistence in between application launches.

The following figure represents the application’s folder structure:

![iOS App Folder Structure](http://bb-conservation.de/sven/iOS.png)


### IPA Payloads, a closer look

Let’s take a closer look now at the different files that are to be found in the ZIP compressed IPA container. It is necessary to understand that this is the raw architecture of the bundle container and not the definitive form after installation on the device. It uses a relatively flat structure with few extraneous directories in an effort to save disk space and simplify access to the files. The bundle contains the application executable and any resources used by the application (for instance, the application icon, other images, and localized content) in the top-level bundle directory.

* **MyApp**: The executable containing the application’s code, which is compiled and not in a ‘readable’ format.
* **Application**: Icons used at specific times to represent the application. 
* **Info.plist**: Containing configuration information, such as its bundle ID, version number, and display name.
* **Launch images**: Images showing the initial interface of the application in a specific orientation. The system uses one of the provided launch images as a temporary background until the application is fully loaded.
* **MainWindow.nib**: Contains the default interface objects to load at application launch time. Other interface objects are then either loaded from additional nib files or created programmatically by the application.
* **Settings.bundle**: Contains any application-specific preferences using property lists and other resource files to configure and display them.
* **Custom resource files**: Non-localized resources are placed at the top level directory and localized resources are placed in language-specific subdirectories of the application bundle. Resources consist of nib files, images, sound files, configuration files, strings files, and any other custom data files you need for your application.

A language.lproj folder is defined for each language that the application supports. It contains the a storyboard and strings files.
* A storyboard is a visual representation of the user interface of an iOS application, showing screens of content and the connections between those screens.
* The strings file format consists of one or more key-value pairs along with optional comments.

![iOS App Folder Structure](http://bb-conservation.de/sven/iOS_project_folder.png)

On a jailbroken device, we can download the installed iOS app (IPA file) using iFunbox, iExplorer, Cyberduck, or any ftp/scp software. Note that during mobile security assessments, developers will often provide you with the IPA directly. They could send you the actual file, or provide access to the development specific distribution platform they use e.g. [HockeyApp] or [Testflight]. 


References:
[usbmuxd](http://www.libimobiledevice.org/)

[usbmux](http://wikee.iphwn.org/usb:usbmux)

[AppSync](https://cydia.angelxwind.net/?page/net.angelxwind.appsyncunified)

[ipainstaller](https://github.com/autopear/ipainstaller)

[Hockey Flight](https://hockeyapp.net/)

[Testflight](https://developer.apple.com/testflight/)
