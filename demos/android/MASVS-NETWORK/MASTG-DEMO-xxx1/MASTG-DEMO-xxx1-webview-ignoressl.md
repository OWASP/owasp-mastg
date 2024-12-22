---
title: WebView Ignoring SSL Certificate Validation
platform: android
works: yes
kind: fail
---

## Overview

Android applications that use `WebView` to load web content may be vulnerable to security risks if they ignore SSL certificate validation. By default, `WebView` validates SSL certificates, ensuring that the connection is secure and the server is trusted. However, developers may disable this validation, allowing the app to communicate with servers using invalid or self-signed certificates.

The following sample code demonstrates how to disable SSL certificate validation in a `WebView` by overriding the `onReceivedSslError` method of the `WebViewClient` class. This method is called when an SSL error occurs during the SSL handshake, allowing developers to handle the error and decide whether to proceed with the connection.

In this case the code is configured to ignore SSL errors, such as expired or self-signed certificates, by calling `handler.proceed()`.

Note that without the `proceed()` call, the `WebView` would log an error and fail to load the content due to the SSL error. For example, `loadUrl("https://expired.badssl.com/")` will fail with:

```plaintext
[ERROR:ssl_client_socket_impl.cc(996)] handshake failed; returned -1, SSL error code 1, net_error -201
```

While `loadUrl("https://self-signed.badssl.com/")` will fail with:

```plaintext
[ERROR:ssl_client_socket_impl.cc(996)] handshake failed; returned -1, SSL error code 1, net_error -202
```

The full list of error codes can be found in the Chromium source code [here](https://chromium.googlesource.com/chromium/src/%2B/main/net/base/net_error_list.h).


## 502 Bad Gateway

Note that if we capture the network traffic using mitmproxy, we can see that the app cannot connect even though it's ignoring the SSL errors.

The 502 Bad Gateway error is not caused by the WebView code’s SSL handling. Even though your WebView `onReceivedSslError` handler calls `handler.proceed()` to ignore SSL errors, the error is happening upstream at mitmproxy before the response reaches the WebView.

Here's why this occurs:

1. **How mitmproxy Works:**  
   Mitmproxy acts as a "man-in-the-middle" proxy. When the app makes an HTTPS request, mitmproxy connects to the remote server (in this case `expired.badssl.com`) on behalf of the app. If the server presents an expired or invalid certificate, mitmproxy—by default—tries to validate it. When it fails, mitmproxy itself cannot establish a proper SSL/TLS connection to the upstream server.

2. **Mitmproxy Returns the Error:**  
   Since mitmproxy can’t connect securely due to the expired certificate, it returns an HTTP error (like a 502 Bad Gateway) to the client (the WebView). At this point, the SSL handshake failure has already occurred upstream. All the WebView sees is a normal HTTP response code (502), not an SSL error it can ignore.

3. **Ignoring SSL Errors in WebView vs. Mitmproxy:**  
   - **In WebView:** Calling `handler.proceed()` in `onReceivedSslError()` tells the WebView to ignore SSL certificate issues presented to it directly. This is useful if the final response from the server has a certificate issue that the WebView can see.
   - **In mitmproxy:** By the time the request reaches mitmproxy, it is mitmproxy that must handle the SSL handshake with the remote server. If that fails, the failure occurs before the WebView even gets a chance to apply its `onReceivedSslError` logic.

4. **Solution - Instruct mitmproxy to Ignore Upstream SSL Errors:**  
   To fix this, you need mitmproxy to accept upstream invalid certificates. You can do this by running mitmproxy with the `--ssl-insecure` option or another configuration that tells mitmproxy not to verify the server’s certificate:
   ```bash
   mitmproxy --ssl-insecure
   ```
   or for mitmdump:
   ```bash
   mitmdump --ssl-insecure --flow-detail 1 -w /tmp/mitmproxy_capture.log
   ```

   or mitmweb:
   ```bash
    mitmweb --ssl-insecure
    ```
   
   With `--ssl-insecure`, mitmproxy will ignore certificate validation errors from the upstream server. It will then pass the data along to the WebView, allowing the `handler.proceed()` call to effectively ignore the SSL issue at the client end.

You can get a 502 error because mitmproxy is failing to negotiate SSL with the upstream host due to the expired certificate. Your WebView code only controls how it handles SSL errors at the client side, not upstream. Adjusting mitmproxy’s settings to ignore upstream SSL errors will solve the problem.

## Steps

We run a semgrep rule to detect instances of the `onReceivedSslError` method being overridden in a `WebViewClient` object and the `handler.proceed()` method being.

## Output

The rule detected on use of `onReceivedSslError` method in the `WebViewClient` class within the MastgTest.kt file. The rule output is as follows:

```plaintext
WebView ignores SSL certificate validation
```

## Evaluation

The test fails because the code overrides the `onReceivedSslError` method in the `WebViewClient` class and calls `handler.proceed()` to ignore SSL certificate validation errors. This practice is insecure and can expose the app to MITM attacks and other security threats. Developers should always validate SSL certificates to ensure secure communication between the app and the server.

## Remediation

To remediate this issue, developers should remove the `onReceivedSslError` method override from the `WebViewClient` class or implement proper SSL certificate validation logic. When an SSL error occurs, developers should handle the error appropriately by either proceeding with the connection after validating the certificate or canceling the connection if the certificate is invalid.
