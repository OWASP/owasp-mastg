### <a name="OMTG-NET-003"></a>OMTG-NET-003: Test SSL Pinning

#### Overview

Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

#### White-box Testing

The process to implement the SSL pinning involves three main steps outlined below:

1. Obtain a certificate for the desired host
1. Make sure certificate is in .bks format
1. Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementations of the SSL pinning the HTTP client should:

1. Load the keystore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the keystore is loaded we can use the TrustManager that trusts the CAs in our KeyStore :

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

#### Black-box Testing

Black-box Testing can be performed by launching a MITM attack using your prefered Web Proxy to intercept the traffic exchanged between client (mobile application) and the backend server. If the Proxy is unable to intercept the HTTP requests/responses, the SSL pinning is correctly implemented.

#### Remediation

The SSL pinning process should be implemented as described on the static analysis section.

#### References

- Setting Burp Suite as a proxy for Android Devices : https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
- OWASP - Certificate Pinning for Android :  https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android
