## Android Network APIs

### Testing Endpoint Identify Verification

Using TLS for transporting sensitive information over the network is essential from security point of view. However, implementing a mechanism of encrypted communication between mobile application and backend API is not a trivial task. Developers often decide for easier, but less secure (e.g. accepting any certificate) solutions to ease the development process, and sometimes these weak solutions [make it into the production version](https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf "Hunting Down Broken SSL in Android Apps"), potentially exposing users to [man-in-the-middle attacks](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation").

There are two key issues that should be tested for:

- verify that a certificate comes from a trusted source and
- check whether the endpoint server presents the right certificate.

Ensure that the hostname and certificate are verified correctly. Examples and common pitfalls can be found in the [official Android documentation](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL"). Search the code for usages of `TrustManager` and `HostnameVerifier`. You can find insecure usage examples in the sections below.

##### Verifying the Server Certificate

A mechanism responsible for verifying conditions to establish a trusted connection in Android is called "TrustManager". Conditions to be checked at this point, are the following:

- Is the certificate signed by a "trusted" CA?
- Is the certificate expired?
- Is the certificate self-signed?

Look in the code if there are control checks of aforementioned conditions. For example, the following code will accept any certificate:

```
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

##### WebView Server Certificate Verification

Sometimes applications use the WebView UI component to render the website associated with the application. This is also the case for HTML/JavaScript based frameworks, like for example Apache Cordova, that internally uses a WebView to perform application interaction. When a WebView is used, it is the mobile browser that performs the server certificate validation. A bad practice would be to ignore any TLS error that occurs when the WebView tries to establish the connection with the remote website.

The following code would ignore any TLS issues, precisely the custom implementation of the WebViewClient provided to the WebView:

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        //Ignore TLS certificate errors and instruct the WebViewClient to load the website
        handler.proceed();
    }
});
```

##### Apache Cordova Certificate Verification

The internal usage of a WebView in the Apache Cordova framework is implemented in a way that [any TLS error is ignored](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") in method `onReceivedSslError` if the flag `android:debuggable` is enabled in the application manifest. Therefore ensure that the app is not debuggable. See also the test case "Testing If the App is Debuggable".

##### Hostname Verification

Another security fault in TLS implementation on client side is a lack of hostname verification. A development environment usually uses some internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code is responsible for disabling hostname verification:

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

It's also possible to accept any hostname using a built-in `HostnameVerifier`:

```Java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Ensure that your application verifies a hostname before setting trusted connection.


#### Dynamic Analysis

A dynamic analysis approach will require usage of intercept proxy. To test improper certificate verification, you should go through following control checks:

 1) Self-signed certificate

  In Burp go to `Proxy -> Options` tab, go to `Proxy Listeners` section, highlight your listener and click `Edit`. Then go to `Certificate` tab and check `Use a self-signed certificate` and click `Ok`. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting self-signed certificates.

 2) Accepting invalid certificate

  In Burp go to `Proxy -> Options` tab, go to `Proxy Listeners` section, highlight your listener and click `Edit`. Then go to `Certificate` tab, check `Generate a CA-signed certificate with a specific hostname` and type a hostname of a backend server. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any certificate.

 3) Accepting wrong hostname.

  In Burp go to `Proxy -> Options` tab, go to `Proxy Listeners` section, highlight your listener and click `Edit`. Then go to `Certificate` tab, check `Generate a CA-signed certificate with a specific hostname` and type in an invalid hostname, e.g. example.org. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any hostname.

If you are interested in further MITM analysis or you face any problems with configuration of your intercept proxy, you may consider using [Tapioca](https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html "Announcing CERT Tapioca for MITM Analysis"). It's a CERT preconfigured [VM appliance](http://www.cert.org/download/mitm/CERT_Tapioca.ova "CERT Tapioca Virtual Machine Download") for performing MITM analysis of software. All you have to do is [deploy a tested application on emulator and start capturing traffic](https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html "Finding Android SSL vulnerabilities with CERT Tapioca").


#### References

#### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
- V5.3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."

##### CWE
- CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
- CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
- CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html


### Testing Custom Certificate Stores and Certificate Pinning

#### Overview

Certificate pinning is the process of associating the backend server with a particular X509 certificate or public key, instead of accepting any certificate signed by a trusted certificate authority. A mobile app that stores ("pins") the server certificate or public key will subsequently only establish connections to the known server. By removing trust in external certificate authorities, the attack surface is reduced (after all, there are many known cases where certificate authorities have been compromised or tricked into issuing certificates to impostors).

The certificate can be pinned during development, or at the time the app first connects to the backend.
In that case, the certificate associated or 'pinned' to the host at when it seen for the first time. This second variant is slightly less secure, as an attacker intercepting the initial connection could inject their own certificate.

#### Static Analysis

The process to implement the certificate pinning involves three main steps outlined below:

1. Obtain a certificate for the desired host
1. Make sure the certificate is in .bks format
1. Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementation of certificate pinning the HTTP client should:

1. Load the Keystore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the Keystore is loaded we can use the TrustManager that trusts the CAs in our KeyStore :

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

The specific implementation in the app might be different, as it might be pinning against only the public key of the certificate, the whole certificate or a whole certificate chain.

Applications that use third-party networking libraries may utilize the certificate pinning functionality in those libraries. For example, [okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") can be set up with the `CertificatePinner` as follows:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("bignerdranch.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

Applications that use a WebView component may utilize the event handler of the WebViewClient in order to perform some kind of "certificate pinning" on each request before the target resource will be loaded. The following code shows an example for verifying the Issuer DN of the certificate sent by the server:

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    private String expectedIssuerDN = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US;";

    @Override
    public void onLoadResource(WebView view, String url)  {
        //From Android API documentation about "WebView.getCertificate()":
        //Gets the SSL certificate for the main top-level page
        //or null if there is no certificate (the site is not secure).
        //
        //Available information on SslCertificate class are "Issuer DN", "Subject DN" and validity date helpers
        SslCertificate serverCert = view.getCertificate();
        if(serverCert != null){
            //Apply check on Issuer DN against expected one
            SslCertificate.DName issuerDN = serverCert.getIssuedBy();
            if(!this.expectedIssuerDN.equals(issuerDN.toString())){
                //Throw exception to cancel resource loading...
            }
        }
    }
});
```

Applications can decide to use the [Network Security Configuration](https://developer.android.com/training/articles/security-config.html "Network Security Configuration documentation") feature provided by Android from version 7.0 onwards, to customize their network security settings in a safe, declarative configuration file without modifying app code.

Network Security Configuration (NSC) feature can also be used to perform [declarative certificate pinning](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") on specific domains. If an application uses the NSC feature then there two points to check in order to identify the defined configuration:

1. Specification of the NSC file reference in the Android application manifest using the "android:networkSecurityConfig" attribute on the application tag:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.com.app">
    <application android:networkSecurityConfig="@xml/network_security_config">
        ...
    </application>
</manifest>
```

2. Content the NSC file stored in location "res/xml/network_security_config.xml" of the module:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <!-- Use certificate pinning for OWASP website access including sub domains -->
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Intermediate CA of the OWASP website server certificate -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Root CA of the OWASP website server certificate -->
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

If a NSC configuration is in place then the following event can be visible in log:

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

If a certificate pinning validation check is failing then the following event will be logged:

```
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

For further information please check the [OWASP certificate pinning guide](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android "OWASP Certificate Pinning for Android").

#### Dynamic Analysis

Dynamic analysis can be performed by launching a MITM attack using your preferred interception proxy. This will allow to monitor the traffic exchanged between client (mobile application) and the backend server. If the Proxy is unable to intercept the HTTP requests and responses, the SSL pinning is correctly implemented.


### Testing the Security Provider

#### Overview
Android relies on a security provider to provide SSL/TLS based connections. The problem with this security provider (for instance [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")) which is packed with the device, is that it often has bugs and/or vulnerabilities.
Developers need to make sure that the application will install a proper security provider to make sure that there will be no known vulnerabilities.
Since July 11 2016, Google [rejects Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) if they are using vulnerable versions of OpenSSL.

#### Static Analysis

In case of an Android SDK based application the application should have a dependency on the GooglePlayServices. For example in a gradle build file, you will find `compile 'com.google.android.gms:play-services-gcm:x.x.x'` in the dependencies block. Next you need to make sure that the `ProviderInstaller` class is called with either `installIfNeeded()` or with `installIfNeededAsync()`. The `ProviderInstaller` needs to be called as early as possible by a component of the application. Exceptions that are thrown by these methods should be caught and handled correctly.
If the application cannot patch its security provider then it can either inform the API on his lesser secure state or it can restrict the user in its possible actions as all HTTPS-traffic should now be deemed more risky.

Here are two [examples from the Android Developer documentation](https://developer.android.com/training/articles/security-gms-provider.html "Updating Your Security Provider to Protect Against SSL Exploits") on how to update your Security Provider to protect against SSL exploits. In both cases, the developer needs to handle the exceptions properly and it might be wise to report to the backend when the application is working with an unpatched security provider.

Patching Synchronously:

```java
//this is a sync adapter that runs in the background, so you can run the synchronous patching.
public class SyncAdapter extends AbstractThreadedSyncAdapter {

  ...

  // This is called each time a sync is attempted; this is okay, since the
  // overhead is negligible if the security provider is up-to-date.
  @Override
  public void onPerformSync(Account account, Bundle extras, String authority,
      ContentProviderClient provider, SyncResult syncResult) {
    try {
      ProviderInstaller.installIfNeeded(getContext());
    } catch (GooglePlayServicesRepairableException e) {

      // Indicates that Google Play services is out of date, disabled, etc.

      // Prompt the user to install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorNotification(
          e.getConnectionStatusCode(), getContext());

      // Notify the SyncManager that a soft error occurred.
      syncResult.stats.numIOExceptions++;
      return;

    } catch (GooglePlayServicesNotAvailableException e) {
      // Indicates a non-recoverable error; the ProviderInstaller is not able
      // to install an up-to-date Provider.

      // Notify the SyncManager that a hard error occurred.
      //in this case: make sure that you inform your API of it.
      syncResult.stats.numAuthExceptions++;
      return;
    }

    // If this is reached, you know that the provider was already up-to-date,
    // or was successfully updated.
  }
}
```

Patching Asynchronously:

```java
//This is the mainactivity/first activity of the application that is there long enough to make the async installing of the securityprovider work.
public class MainActivity extends Activity
    implements ProviderInstaller.ProviderInstallListener {

  private static final int ERROR_DIALOG_REQUEST_CODE = 1;

  private boolean mRetryProviderInstall;

  //Update the security provider when the activity is created.
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ProviderInstaller.installIfNeededAsync(this, this);
  }

  /**
   * This method is only called if the provider is successfully updated
   * (or is already up-to-date).
   */
  @Override
  protected void onProviderInstalled() {
    // Provider is up-to-date, app can make secure network calls.
  }

  /**
   * This method is called if updating fails; the error code indicates
   * whether the error is recoverable.
   */
  @Override
  protected void onProviderInstallFailed(int errorCode, Intent recoveryIntent) {
    if (GooglePlayServicesUtil.isUserRecoverableError(errorCode)) {
      // Recoverable error. Show a dialog prompting the user to
      // install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorDialogFragment(
          errorCode,
          this,
          ERROR_DIALOG_REQUEST_CODE,
          new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
              // The user chose not to take the recovery action
              onProviderInstallerNotAvailable();
            }
          });
    } else {
      // Google Play services is not available.
      onProviderInstallerNotAvailable();
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode,
      Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == ERROR_DIALOG_REQUEST_CODE) {
      // Adding a fragment via GooglePlayServicesUtil.showErrorDialogFragment
      // before the instance state is restored throws an error. So instead,
      // set a flag here, which will cause the fragment to delay until
      // onPostResume.
      mRetryProviderInstall = true;
    }
  }

  /**
   * On resume, check to see if we flagged that we need to reinstall the
   * provider.
   */
  @Override
  protected void onPostResume() {
    super.onPostResult();
    if (mRetryProviderInstall) {
      // We can now safely retry installation.
      ProviderInstall.installIfNeededAsync(this, this);
    }
    mRetryProviderInstall = false;
  }

  private void onProviderInstallerNotAvailable() {
    // This is reached if the provider cannot be updated for some reason.
    // App should consider all HTTP communication to be vulnerable, and take
    // appropriate action (e.g. inform backend, block certain high-risk actions, etc.).
  }
}

```

In case of an NDK based application: make sure that the application does only bind to a recent and properly patched library that provides SSL/TLS functionality.

#### Dynamic Analysis

When you have the source-code:
- Run the application in debug mode, then make a breakpoint right where the app will make its first contact with the endpoint(s).
- Right click at the code that is highlighted and select `Evaluate Expression`
- Type `Security.getProviders()` and press enter
- Check the providers and see if you can find `GmsCore_OpenSSL` which should be the new toplisted provider.

When you do not have the source-code:
- Use Xposed to hook into `java.security` package, then hook into `java.security.Security` with the method `getProviders` with no arguments. The return value is an Array of `Provider`.
- Check if the first provider is `GmsCore_OpenSSL`.

### References

#### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

#### OWASP MASVS
- V5.4: "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."
- V5.6: "The app only depends on up-to-date connectivity and security libraries."

#### CWE
- CWE-295 - Improper Certificate Validation
