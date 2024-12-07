---
title: WebView Ignoring SSL Certificate Validation for Pinned Certificate
platform: android
works: yes
kind: fail
---

Apps can pin invalid certificates in a `WebView` by implementing custom certificate validation. They can do this by intercepting the SSL handshake in the `onReceivedSslError` callback and manually validating the certificate against the pinned certificate.

1. **Obtain the Certificate**: Extract the self-signed certificate in `.crt` or `.pem` format from the server and place it in your app's `res/raw` directory.

   - Use `openssl` to retrieve the certificate:

    ```bash
    echo | openssl s_client -connect self-signed.badssl.com:443 | openssl x509 > selfsigned.crt
    ```

2. **Pinned Certificate**:
   - The `.crt` file is loaded from `res/raw` and converted to an `X509Certificate`.

3. **Server Certificate**:
   - The `SslError` object provides the server's certificate, which is converted to `X509Certificate` for comparison.

4. **Certificate Comparison**:
   - The certificates are compared using `equals()`. This ensures that both the public key and metadata match.

5. **Security Check**:
   - If the certificates match, the WebView proceeds with the connection (`handler.proceed()`).
   - If they don’t match, the connection is canceled (`handler.cancel()`).

If the certificates don't match the app will log:

```txt
Certificates don't match, cancelling
[ERROR:ssl_client_socket_impl.cc(996)] handshake failed; returned -1, SSL error code 1, net_error -201
```

## Steps

We run a semgrep rule to detect the use of `CertificateFactory` and `onReceivedSslError` method in the `WebViewClient` class.

## Output

The semgrep rule detected the use of `CertificateFactory` and `onReceivedSslError` method in the `WebViewClient` class within the MastgTest.kt file. The rule output is as follows:

```plaintext
WebView ignores SSL certificate validation
```

## Evaluation

The test fails because the code is configured to ignore SSL errors, such as expired or self-signed certificates, by calling `handler.proceed()`. This bypasses the SSL certificate validation, which can expose the app to security risks. To fix this, the app should implement custom certificate validation and compare the server's certificate with a pinned certificate to ensure secure communication.
