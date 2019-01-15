# Adding a new test case 

- Add a new blank activity and call it accordingly to the test case. For example "OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data" will become OMTG_DATAST_005_Keyboard_Cache.java.

- In res/layout/ there is a new file created called `content_<ClassName>.xml`. In this file the layout and elements can be specified (textarea, input etc.).  

- Put an new method into MyActivity.java:

```java
    public void OMTG_DATAST_00X_ClassName(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_00X_ClassName.class);
        startActivity(intent);
    }
```

- Add the test case content

- Run the App and it should be deployed to your phone/emulator with the new test case.

- Raise a ticket if you have problems. 


# Overview of Test Cases in Android App


## OMTG_DATAST_001_BadEncryption

### Description 

The activity contains an encrypted string (vJqfip28ioydips=). The encryption function provided does only a XOR and flips the bits after the XOR. 

To decrypt the String the following function can be used. This function is not part of the code, but can easily be created when understanding  the encrypt function.

```Java

    protected void onCreate(Bundle savedInstanceState) {
        
        decrypt("vJqfip28ioydips=");
        

    private void decrypt(String str) {
        byte[] bytes = Base64.decode(str, Base64.DEFAULT);

        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ 16);
            int curr =  ~bytes[i] & 0xff;
            bytes[i] = (byte) curr;
        }

        String decryptedData = new String(bytes);
        Log.e("Decrypted Password", decryptedData);
    }
```

### Intention

To show that you need to use proper Encryption libraries and functions and do not try to create your own encryption algorithms which might be easily reverse engineered. 

## OMTG_DATAST_001_KeyChain

### Description 

This activity is importing a certificate, which is stored in the assets directory (server.p12). The password to import is 1234.  

### Intention

Show a best practice on how to import a certificate into the KeyChain. 


## OMTG_DATAST_001_KeyStore

### Description 

This activity is creating a key pair and using the generated key *alias* dummy for encrypting and decrypting a string. 

### Intention

Show a best practice on how to create a key pair by using KeyStore and how to encrypt/decrypt data. 



## OMTG_DATAST_001_InternalStorage

### Description 

This activity is showing how to store data to the internal storage. A file called test_file will be created in /data/data/sg.vp.owasp_mobile.myfirstbrokenapp/files that contains a credit card number. 

### Intention

Show that storing data on the device itself can lead to disclosure of data. Usage of internal storage should not be used for sensitive information. 


## OMTG_DATAST_001_ExternalStorage

### Description 

This activity is showing how to store data to the external storage. A file called password.txt will be created in the external storage dir (might be different on different Android versions). The folder is /storage/emulated/0 on the Xiami Note 2.   

### Intention

Show that storing data on the device itself can lead to disclosure of data. Usage of external storage should not be used for storing information for the app as external storage can be accessed by all Apps and can also be removed which might lead to errors in the app. 


## OMTG_DATAST_001_SharedPreferences

### Description 

This activity is showing how to create Shared Preferences. As a bad practice user credentials are stored as key-value pair in the file key.xml in /data/data/sg.vp.owasp_mobile.omtg_android/shared_prefs.

### Intention

To show that no sensitive information should be stored in Shared Preferences as it is stored by default in clear text. 

## OMTG_DATAST_001_SQLite_Not_Encrypted

### Description 

This activity is showing how to create a SQLite database. As a bad practice user credentials are stored in the database. 

### Intention

To show that no sensitive information should be stored in a SQLite database as it is stored by default in clear text. 


## OMTG_DATAST_001_SQLite_Encrypted

### Description 

This activity is showing how to create an encrypted SQLite database by using SQLCipher. As a bad practice user credentials are stored in an encrypted database, but the key is stored locally in the App.

```bash
root@hermes:/data/app/sg.vp.owasp_mobile.myfirstbrokenapp-2/lib/arm # ls -la
-rwxr-xr-x system   system     186220 1979-12-31 14:36 libdatabase_sqlcipher.so
-rwxr-xr-x system   system      13768 1979-12-31 14:36 libnative.so
-rwxr-xr-x system   system    2277928 1979-12-31 14:36 libsqlcipher_android.so
-rwxr-xr-x system   system     365880 1979-12-31 14:36 libstlport_shared.so
root@hermes:/data/app/sg.vp.owasp_mobile.myfirstbrokenapp-2/lib/arm # strings libnative.so | grep -v _                                               
/system/bin/linker
LIBC
libc.so
libnative.so
memcpy
abort
libstdc++.so
libm.so
libdl.so
S3cr3tString!!!
```

The key cannot easily be retrieved, as it is hidden inside a Shared Object (.so file). Only when looking into the .so file the password can be retrieved (S3cr3tString!!!).



### Intention

It is a best practice to encrypt the SQLite database, but the problem is where to store the key. This shows that there is no way to hide a key locally against an attacker. If the key is stored locally it can be recovered, even though resilience countermeasures can be in place to slow down the attacker. 
To mitigate saving the key locally, the following two approaches can be considered: 
* ask for a password when the app starts that is used to generate the key (likely to be prone to brute force attacks if the password is weak), or
* store the key on the server, then the app can only be used if the app is online.


## OMTG_DATAST_002_Logging

### Description 

This activity is showing a login prompt. Once Login is clicked logs have been created. 

### Intention

Show that logging sensitive data is leading to information disclosure. Even if debugging is disabled in the AndroidManifest, the app can be repackaged and debugging can be enabled. Therefore all logging and debugging code should be deleted before creating a production release. 

## OMTG_DATAST_004_3rd_Party

### Description 

This activity is offering a button to crash the App. If an interception proxy like Burp is used, it can be seen that requests are being sent to https://sushi2k.cloudant.com/acra/_design/acra-storage/_update/report. The open source library ACRA (Application Crash Reports for Android) is used that helps the App to send crash reports to a defined backend (cloudant in this case). The initialisation of ACRA is done by creating a new class called MyApplication. 

### Intention

To show that 3rd party libraries are sending data to their services and that there is a need to have a look at either the code of the library or at least at the HTTP requests to investigate if sensitive information is sent (either on purpose or by accident).  


## OMTG_DATAST_005_Keyboard_Cache

### Description 

This activity is offering a text field to key in data and implements a best practice to deactivate the keyboard cache that would suggest possible inputs. 

### Intention

To show that input/text fields that ask for sensitive data should have deactivated the keyboard cache to not disclose information. 


## OMTG_DATAST_011_Memory

### Description 

This activity is showing how a string is decrypted but the value can only be read if a memory dump is made.  

### Intention

To show that a memory dump can leak sensitive information like decrypted information or keys. 


## OMTG_CODING_005_WebView_Remote

### Description 

This activity is simulating a WebView that is loading a remote page. When the following page is loaded the addJavascriptInterface method in the class OMTG_ENV_005_JS_Interface can be called by the JavaScript embedded in this webpage.  

```HTML
<HTML>

<body>
<h1 style="color: #5e9ca0;">This is a remote test page!</h1>
<p id="p1">2</p>
<input type="button" value="Press here to trigger Toast Message" onclick="fireToastMessage()" />
        <script>
                // test if JavaScript is activated
                alert(23);
               // call returnString method in Java Class
                var result = window.Android.returnString();
                document.getElementById("p1").innerHTML = result;

               // trigger manually a toast message from JavaScript
                function fireToastMessage() {
                        window.Android.showToast("this is executed by JavaScript");
                }
        </script>
</body>
</HTML>
```
The Website is also available here: https://github.com/sushi2k/AndroidWebView

### Intention

To show that by using addJavascriptInterface() it is possible for JavaScript to execute Java methods. This might never be a good idea and should be avoided. If it's needed only JavaScript provided with the APK should be allowed to call it but no JavaScript loaded from a remote endpoints. 


## OMTG_CODING_005_WebView_Local 

### Description 

This activity is simulating a WebView that is loading a local page. The local page is loading JavaScript from a remote server: 

```JavaScript
// check if JavaScript is activated
//popup();

var elem = document.createElement("img");
document.getElementById("div1").appendChild(elem);
// access to external storage
elem.src = "file:///storage/emulated/0/Bsd_daemon.jpg";
// access to asset directory of App
//elem.src = "file:///android_asset/Bsd_daemon.jpg";

// this only works if setAllowFileAccessFromFileURLs() is enabled (disabled by default)
var file = "file:///data/data/sg.vp.owasp_mobile.myfirstbrokenapp/shared_prefs/key.xml";

var xhr = new XMLHttpRequest();
xhr.overrideMimeType("text/plain; charset=iso-8859-1");
xhr.open("GET", file, true);
xhr.onreadystatechange = function() {
 var data = xhr.responseText;
 alert(data);
}
xhr.send();

function popup() {
alert("Hello World")
}
```

This JavaScript is able to access sensitive data from the App in the directory SharedPreferences. Before executing this, the test case OMTG_DATAST_004_SharedPreferences should be run first, to create the XML file that is read by the JavaScript. 

The JavaScript is also available here: https://github.com/sushi2k/AndroidWebView

### Intention

To show that activating setAllowFileAccessFromFileURLs() can lead to serious vulnerabilities, if the JavaScript code can be influenced by an attacker (e.g. MiTM position or able to modify the JavaScript file if it is stored on the external storage). 


## OMTG_CODING_003_Best_Practice

### Description 

This activity is simulating a local login where the authentication is done against a local SQLite database. The SQL query is implemented according to best practice. 

### Intention

To show a best practice on how a SQL query should be implemented when using rawQuery to avoid SQL injection. See OMTG_CODING_003_SQL_Injection and OMTG_CODING_003_SQL_Injection_Content_Provider for 'Bad Practices'. 


## OMTG_CODING_003_SQL_Injection

### Description 

This activity is simulating a local login where the authentication is done against a local SQLite database. The SQL query is prone to SQL injection. 

### Intention

To show that SQL injection is also possible locally on an Android Device. Even if the risk is only locally on the device itself, prepared statements should always be used to mitigate SQL Injection. 


## OMTG_CODING_003_SQL_Injection_Content_Provider

### Description 

This activity is simulating a basic student database (sample used from http://www.tutorialspoint.com/android/android_content_providers.htm) to create student records and query them. The SQLite database is available via a Content Provider. The Content Provider is prone to SQL injection. 

### Intention

To show that SQL injection is also possible via a Content Provider.  When being on a rooted device the command content can be used to query the data. 

```content query --uri content://sg.vp.owasp_mobile.provider.College/students```

And also insert students, this sample inserts a student called Alice with grade A:

```content insert --uri content://sg.vp.owasp_mobile.provider.College/students --bind name:s:Alice --bind grade:s:A```

The SQL injection can be exploited by using the following command. Instead of getting the record for Bob all data can be retrieved. 

```content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''" ```

Even if the risk is only locally on the device itself, prepared statements should always be used to mitigate SQL Injection. SQL Injection attacks are also possible through malicious Apps if the functionality that is prone to SQL injection is exported and available to other Apps. 


## OMTG_CODING_004_Code_Injection

### Description 

This activity is simulating Code Injection by using the Class DexClassLoader. A jar file called libcodeinjection.jar is dynamically loaded from the external storage and the class and it's function returnString() is executed. 

The Jar was created like this:
- A new blank project was created in Android Studio.
- File/New/New Module was selected to create a new Java library. 
- Source Code can be found here: TBD
- Jar can be build by clicking on the right side on Grade, then Code_Injection/Code_Injection (root)/Tasks/build and then double click on build. 
- The JAR is in the directory Code_Injection/libcodeinjection/build/libs
- The JAR needs to be in DEX format for the Android Platform therefore the following command needs to be executed:

```dx --dex --output=libcodeinjection.dex libcodeinjection.jar```

The dex file needs to be renamed to classes.dex and packed again into a jar

```
mv libcodeinjection.dex classes.dex
jar cfv libcodeinjection.jar classes.dex
```
The file libcodeinjection.jar needs to be copied to the external storage of the Android Phone. See the Logfiles for execution of the function returnString():

```sg.vp.owasp_mobile.myfirstbrokenapp E/Test: The class com.example.CodeInjection and it's method returnString was just called```

The Jar file can be downloaded here: https://github.com/sushi2k/libCodeInjection 


### Intention

To show that loading of external JAR files dynamically is possible in Android. This should only be used very carefully and is not considered a best practice.


## OMTG_NETW_001_Secure_Channel

### Description

This activity loads a web-page once using `http` and once using `https`.

### Intention

To show that using insecure channel (`http`) where secure channel (`https`) is available can be dangerous and all the traffic can be monitored and can even be modified using attacks like MiTM.

