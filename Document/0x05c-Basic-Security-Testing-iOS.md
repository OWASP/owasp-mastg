## iOS

### Static Analysis

#### With Source Code

#### Without Source Code

##### Recovering an IPA file from an installed app

###### From Jailbroken devices

You can use Saurik's IPA Installer to recover IPAs from apps installed on the device. To do this, install [IPA installer console](http://cydia.saurik.com/package/com.autopear.installipa/) via Cydia. Then, ssh into the device and look up the bundle id of the target app. For example:

~~~
iPhone:~ root# ipainstaller -l
com.apple.Pages
com.example.targetapp
com.google.ios.youtube
com.spotify.client
~~~

Generate the IPA file for using the following command:

~~~
iPhone:~ root# ipainstaller -b com.example.targetapp -o /tmp/example.ipa
~~~

###### From non-Jailbroken devices

If the app is available on itunes, you are able to recover the ipa on MacOS with the following simple steps:

- Download the app in itunes
- Go to your itunes Apps Library
- Right-click on the app and select show in finder

(... TODO...)

#### Dumping Decrypted Executables

On top of code signing, apps distributed via the app store are also protected using Apple's FairPlay DRM system. This system uses asymmetric cryptography to ensure that any app (including free apps) obtained from the app store only executes on the particular device it is approved to run on. The decryption key is unique to the device and burned into the processor. As of now, the only possible way to obtain the decrypted code from a FairPlay-decrypted app is dumping it from memory while the app is running. On a jailbroken device, this can be done with Stefan Esser's dumpdecrypted tool [1].

Connect to the iOS device using SSH and set the DYLD_INSERT_LIBRARIES environment variable when executing the target binary:

~~~
ssh root@<ip of idevice>
iPod:root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/Example.app/Example
~~~

The decrypted binary is saved in the current working directory.

#### References

* [1] Dumpdecrypted - https://github.com/stefanesser/dumpdecrypted

### Dynamic Analysis


#### On Jailbroken devices


#### On non-Jailbroken Devices


References:

http://cydia.saurik.com/package/com.autopear.installipa/
