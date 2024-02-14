---
title: Logging Sensitive Data from Network Traffic
platform: android
---

[mitmproxy](MASTG-TOOL-0097) can be used to intercept network traffic from Android apps. This technique is useful for identifying sensitive data that is sent over the network, as well as for identifying potential security vulnerabilities.

Once with mitmproxy installed and your device configured to use it, you can create a python script to filter the traffic and extract the sensitive data. For example, the following script will extract all the data sent in the requests and responses only if the data is considered sensitive. For this example we consider sensitive data to be any data that contains the strings "dummyPassword" or "sampleUser", so we include them in the `SENSITIVE_STRINGS` list.

```python
# mitm_sensitive_logger.py

from mitmproxy import http

# This data would come from another file and should be defined after identifying the data that is considered sensitive for this application.
# For example by using the Google Play Store Data Safety section.
SENSITIVE_DATA = {
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194",
    "name": "John Doe",
    "email_address": "john.doe@example.com",
    "phone_number": "+11234567890",
    "credit_card_number": "1234 5678 9012 3456"
}

SENSITIVE_STRINGS = SENSITIVE_DATA.values()

def contains_sensitive_data(string):
    return any(sensitive in string for sensitive in SENSITIVE_STRINGS)

def process_flow(flow):
    url = flow.request.pretty_url
    request_headers = flow.request.headers
    request_body = flow.request.text
    response_headers = flow.response.headers if flow.response else "No response"
    response_body = flow.response.text if flow.response else "No response"

    if (contains_sensitive_data(url) or 
        contains_sensitive_data(request_body) or 
        contains_sensitive_data(response_body)):
        with open("sensitive_data.log", "a") as file:
            if flow.response:
                file.write(f"RESPONSE URL: {url}\n")
                file.write(f"Response Headers: {response_headers}\n")
                file.write(f"Response Body: {response_body}\n\n")
            else:
                file.write(f"REQUEST URL: {url}\n")
                file.write(f"Request Headers: {request_headers}\n")
                file.write(f"Request Body: {request_body}\n\n")
def request(flow: http.HTTPFlow):
    process_flow(flow)

def response(flow: http.HTTPFlow):
    process_flow(flow)
```

Now you can run mitmproxy with the script:

```bash
mitmdump -s mitm_sensitive_logger.py
```

Our example app has this code:

```java
fun testPostRequest() {
    val thread = Thread {
        try {
            val url = URL("https://httpbin.org/post")
            val httpURLConnection = url.openConnection() as HttpURLConnection
            httpURLConnection.requestMethod = "POST"
            httpURLConnection.doOutput = true
            httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            val user = "sampleUser"
            val password = "dummyPassword"

            val postData = "username=$user&password=$password"

            val outputStream = BufferedOutputStream(httpURLConnection.outputStream)
            val bufferedWriter = BufferedWriter(OutputStreamWriter(outputStream, "UTF-8"))
            bufferedWriter.write(postData)
            bufferedWriter.flush()
            bufferedWriter.close()
            outputStream.close()

            val responseCode = httpURLConnection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                Log.d("HTTP_SUCCESS", "Successfully authenticated.")
            } else {
                Log.e("HTTP_ERROR", "Failed to authenticate. Response code: $responseCode")
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
    thread.start()
}
```

The app sends a POST request to `https://httpbin.org/post` with the body `username=sampleUser&password=dummyPassword`. `httpbin.org` is a website that returns the request data in the response body, so we can see the data that was sent in the request.

Run the app and use it as you normally would. The script will log any sensitive data that is sent over the network to the `sensitive_data.log` file.

Example console output:

```bash
[10:07:59.348] Loading script mitm_sensitive_logger.py
[10:07:59.351] HTTP(S) proxy listening at *:8080.
[10:08:08.188][127.0.0.1:64701] server connect httpbin.org:443 (52.206.94.89:443)
[10:08:08.192][127.0.0.1:64709] server connect mas.owasp.org:443 (104.22.27.77:443)
[10:08:08.245][127.0.0.1:64709] Client TLS handshake failed. The client does not trust the proxy's certificate for mas.owasp.org (OpenSSL Error([('SSL routines', '', 'ssl/tls alert certificate unknown')]))
[10:08:08.246][127.0.0.1:64709] client disconnect
[10:08:08.246][127.0.0.1:64709] server disconnect mas.owasp.org:443 (104.22.27.77:443)
127.0.0.1:64701: POST https://httpbin.org/post
              << 200 OK 548b
```

Example `sensitive_data.log` output:

```bash
REQUEST URL: https://httpbin.org/post
Request Headers: Headers[(b'Content-Type', b'application/x-www-form-urlencoded'), (b'User-Agent', b'Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.021)'), (b'Host', b'httpbin.org'), (b'Connection', b'Keep-Alive'), (b'Accept-Encoding', b'gzip'), (b'Content-Length', b'42')]
Request Body: username=sampleUser&password=dummyPassword

RESPONSE URL: https://httpbin.org/post
Response Headers: Headers[(b'Date', b'Tue, 16 Jan 2024 09:08:08 GMT'), (b'Content-Type', b'application/json'), (b'Content-Length', b'548'), (b'Connection', b'keep-alive'), (b'Server', b'gunicorn/19.9.0'), (b'Access-Control-Allow-Origin', b'*'), (b'Access-Control-Allow-Credentials', b'true')]
Response Body: {
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {
    "password": "dummyPassword", 
    "username": "sampleUser"
  }, 
  "headers": {
    "Accept-Encoding": "gzip", 
    "Content-Length": "42", 
    "Content-Type": "application/x-www-form-urlencoded", 
    "Host": "httpbin.org", 
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.021)", 
    "X-Amzn-Trace-Id": "Root=1-65a64778-78495e9f5d742c9b0c7a75d8"
  }, 
  "json": null, 
  "origin": "148.141.65.87", 
  "url": "https://httpbin.org/post"
}
```
