## iOS

### Static Analysis

#### With Source Code

#### Without Source Code

##### Recovering an IPA file from an installed app

###### On Jailbroken devices

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

###### On non-Jailbroken devices

On a non jailbreakon device, you are able to recover the ipa on MacOS with the following simple steps: 

- Download the app in itunes
- Go to your itunes Apps Library 
- Right-click on the app and select show in finder


References:

http://cydia.saurik.com/package/com.autopear.installipa/
