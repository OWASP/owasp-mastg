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