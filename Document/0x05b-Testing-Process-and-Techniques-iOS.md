## iOS

### White-box Testing

### Black-box Testing

#### Recovering an IPA file from an installed app

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

References:

http://cydia.saurik.com/package/com.autopear.installipa/
