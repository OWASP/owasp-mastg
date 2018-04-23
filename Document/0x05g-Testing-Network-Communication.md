
## Android Network APIs

### Testing Endpoint Identify Verification

Using TLS to transport sensitive information over the network is essential for security. However, encrypting communication between a mobile application and its backend API is not trivial. Developers often decide on simpler but less secure solutions (e.g., those that accept any certificate) to facilitate the development process, and sometimes these weak solutions [make it into the production version](https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf "Hunting Down Broken SSL in Android Apps"), potentially exposing users to [man-in-the-middle attacks](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation").

Two key issues should be addressed:

- Verify that a certificate comes from a trusted source (CA).
- Determine whether the endpoint server presents the right certificate.

Make sure that the hostname and the certificate itself are verified correctly. Examples and common pitfalls are available in the [official Android documentation](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL"). Search the code for examples of `TrustManager` and `HostnameVerifier` usage. In the sections below, you can find examples of the kind of insecure usage that you should look for.

#### Static Analysis

##### Verifying the Server Certificate

"TrustManager" is a means of verifying conditions necessary for establishing a trusted connection in Android. The following conditions should be checked at this point:

- Has the certificate been signed by a "trusted" CA?
- Has the certificate expired?
- Is the certificate self-signed?

The following code snippet is sometimes used during development and will accept any certificate, overwriting the functions `checkClientTrusted`, `checkServerTrusted`, and `getAcceptedIssuers`. Such implementations should be avoided, and, if they are necessary, they should be clearly separated from production builds to avoid built-in security flaws.

```Java
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

Sometimes applications use a WebView to render the website associated with the application. This is true of HTML/JavaScript-based frameworks such as Apache Cordova, which uses an internal WebView for application interaction. When a WebView is used, the mobile browser performs the server certificate validation. Ignoring any TLS error that occurs when the WebView tries to connect to the remote website is a bad practice.

The following code will ignore TLS issues, exactly like the WebViewClient custom implementation provided to the WebView:

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

Implementation of the Apache Cordova framework's internal WebView usage will ignore [TLS errors](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") in the method `onReceivedSslError` if the flag `android:debuggable` is enabled in the application manifest. Therefore, make sure that the app is not debuggable. See the test case "Testing If the App is Debuggable."

##### Hostname Verification

Another security flaw in client-side TLS implementations is the lack of hostname verification. Development environments usually use internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code disables hostname verification:

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

With a built-in `HostnameVerifier`, accepting any hostname is possible:

```Java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Make sure that your application verifies a hostname before setting a trusted connection.


#### Dynamic Analysis

Dynamic analysis requires an interception proxy. To test improper certificate verification, check the following controls:

- Self-signed certificate

In Burp, go to the `Proxy -> Options` tab, then go to the `Proxy Listeners` section, highlight your listener, and click `Edit`. Then go to the `Certificate` tab, check `Use a self-signed certificate`, and click `Ok`. Now, run your application. If you're able to see HTTPS traffic, your application is accepting self-signed certificates.

- Accepting invalid certificates

In Burp, go to the `Proxy -> Options` tab, then go to the `Proxy Listeners` section, highlight your listener, and click `Edit`. Then go to the `Certificate` tab, check `Generate a CA-signed certificate with a specific hostname`, and type in the backend server's hostname. Now, run your application. If you're able to see HTTPS traffic, your application is accepting all certificates.

- Accepting incorrect hostnames

In Burp, go to the `Proxy -> Options` tab, then go to the `Proxy Listeners` section, highlight your listener, and click `Edit`. Then go to the `Certificate` tab, check `Generate a CA-signed certificate with a specific hostname`, and type in an invalid hostname, e.g., example.org. Now, run your application. If you're able to see HTTPS traffic, your application is accepting all hostnames.

If you're interested in further MITM analysis or you have problems with the configuration of your interception proxy, consider using [Tapioca](https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html "Announcing CERT Tapioca for MITM Analysis"). It's a CERT pre-configured [VM appliance](http://www.cert.org/download/mitm/CERT_Tapioca.ova "CERT Tapioca Virtual Machine Download") for MITM software analysis. All you have to do is [deploy a tested application on an emulator and start capturing traffic](https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html "Finding Android SSL vulnerabilities with CERT Tapioca").


### Testing Custom Certificate Stores and Certificate Pinning

#### Overview

Certificate pinning is the process of associating the backend server with a particular X509 certificate or public key instead of accepting any certificate signed by a trusted certificate authority. After storing ("pinning") the server certificate or public key, the mobile app will subsequently connect to the known server only. Withdrawing trust from external certificate authorities reduces the attack surface (after all, there are many cases of certificate authorities that have been compromised or tricked into issuing certificates to impostors).

The certificate can be pinned and hardcoded into the app or retrieved at the time the app first connects to the backend. In the latter case, the certificate is associated with ("pinned" to) the host when the host is seen for the first time. This alternative is less secure because attackers intercepting the initial connection can inject their own certificates.

#### Static Analysis

##### Network Security Configuration

To customize their network security settings in a safe, declarative configuration file without modifying app code, applications can use the [Network Security Configuration (NSC)](https://developer.android.com/training/articles/security-config.html "Network Security Configuration documentation") that Android provides for versions 7.0 and above.

The Network Security Configuration feature can also be used to pin [declarative certificates](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") to specific domains. If an application uses the NSC feature, two things should be checked to identify the defined configuration:

1. Specification of the NSC file reference in the Android application manifest via the "android:networkSecurityConfig" attribute on the application tag:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.com.app">
    <application android:networkSecurityConfig="@xml/network_security_config">
        ...
    </application>
</manifest>
```

2. Contents of the NSC file stored in "res/xml/network_security_config.xml":

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

If an NSC configuration exists, the following event may be visible in the log:

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

If a certificate pinning validation check has failed, the following event will be logged:

```
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

##### TrustManager

Implementing certificate pinning involves three main steps:

- Obtain the certificate of the desired host(s).
- Make sure the certificate is in .bks format.
- Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementation of certificate pinning, the HTTP client should load the Keystore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the Keystore has been loaded, we can use the TrustManager that trusts the CAs in our KeyStore:

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

The app's implementation may be different, pinning against the certificate's public key only, the whole certificate, or a whole certificate chain.

##### Network Libraries and WebViews

Applications that use third-party networking libraries may utilize the libraries' certificate pinning functionality. For example, [okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") can be set up with the `CertificatePinner` as follows:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

Applications that use a WebView component may utilize the WebViewClient's event handler for some kind of "certificate pinning" of each request before the target resource is loaded. The following code shows an example verification of the Issuer DN of the certificate sent by the server:

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

For further information, please check the [OWASP certificate pinning guide](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android "OWASP Certificate Pinning for Android").

#### Dynamic Analysis

Dynamic analysis can be performed by launching a MITM attack with your preferred interception proxy. This will allow you to monitor the traffic between the client (the mobile application) and the backend server. If the proxy is unable to intercept the HTTP requests and responses, the SSL pinning has been implemented correctly.


### Testing the Security Provider

#### Overview
Android relies on a security provider to provide SSL/TLS-based connections. The problem with this kind of security provider (one example is [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")), which comes with the device, is that it often has bugs and/or vulnerabilities.
To avoid known vulnerabilities, developers need to make sure that the application will install a proper security provider.
Since July 11, 2016, Google [has been rejecting Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) that use vulnerable versions of OpenSSL.

#### Static Analysis

Applications based on the Android SDK should depend on GooglePlayServices. For example, in the gradle build file, you will find `compile 'com.google.android.gms:play-services-gcm:x.x.x'` in the dependencies block. You need to make sure that the `ProviderInstaller` class is called with either `installIfNeeded` or `installIfNeededAsync`. `ProviderInstaller` needs to be called by a component of the application as early as possible. Exceptions thrown by these methods should be caught and handled correctly.
If the application cannot patch its security provider, it can either inform the API of its less secure state or restrict user actions (because all HTTPS traffic should be deemed riskier in this situation).

Here are two [examples from the Android Developer documentation](https://developer.android.com/training/articles/security-gms-provider.html "Updating Your Security Provider to Protect Against SSL Exploits") that show how to update Security Provider to prevent SSL exploits. In both cases, the developer needs to handle the exceptions properly, and reporting to the backend when the application is working with an unpatched security provider may be wise.

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
//This is the mainactivity/first activity of the application that's there long enough to make the async installing of the securityprovider work.
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

Make sure that NDK-based applications bind only to a recent and properly patched library that provides SSL/TLS functionality.

#### Dynamic Analysis

When you have the source code:
- Run the application in debug mode, then create a breakpoint where the app will first contact the endpoint(s).
- Right click the highlighted code and select `Evaluate Expression`.
- Type `Security.getProviders()` and press enter.
- Check the providers and try to find `GmsCore_OpenSSL`, which should be the new top-listed provider.

When you do not have the source code:
- Use Xposed to hook into the `java.security` package, then hook into `java.security.Security` with the method `getProviders` (with no arguments). The return value will be an array of `Provider`.
- Determine whether the first provider is `GmsCore_OpenSSL`.


#### References

#### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
- V5.3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."
- V5.4: "The app either uses its own certificate store or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."
- V5.6: "The app only depends on up-to-date connectivity and security libraries."

##### CWE
- CWE-295 - Improper Certificate Validation
- CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
- CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
- CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html
