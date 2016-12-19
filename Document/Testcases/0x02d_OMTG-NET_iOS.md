## <a name="OMTG-NET-004"></a>OMTG-NET-004: Test SSL Pinning

#### Overview

Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

### White-box Testing

The code presented below shows how it is possible to check if the certificate provided by the server reflects the certificate hard-coded  in the application. The method below implements the connection authentication tells the delegate that the connection will send a request for an authentication challenge.

The delegate must implement connection:canAuthenticateAgainstProtectionSpace: and connection: forAuthenticationChallenge. Within connection: forAuthenticationChallenge, the delegate must call SecTrustEvaluate to perform customary X509 checks. Below a snippet who implements a check of the certificate.  

```Objective-C
(void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"MyLocalCertificate" ofType:@"cer"];
NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
The control below can verify if the certificate received by the server is matching the one pinned in the client.
if ([remoteCertificateData isEqualToData:localCertData]) {
NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
[[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}
else {
[[challenge sender] cancelAuthenticationChallenge:challenge];
}
```

### Black-box Testing

Dynamic analysis can be done by following the same methodology used for the Android applications.

### Remediation

The SSL pinning process should be implemented as described on the static analysis section.

### References

- Setting Burp Suite as a proxy for iOS Devices : https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp
References
- OWASP - Certificate Pinning for iOS : https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
