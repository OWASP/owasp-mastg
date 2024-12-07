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
