val SENSITIVE_DATA = mapOf(
    "precise_location_latitude" to "37.7749",
    "precise_location_longitude" to "-122.4194",
    "name" to "John Doe",
    "email_address" to "john.doe@example.com",
    "phone_number" to "+11234567890",
    "credit_card_number" to "1234 5678 9012 3456"
)

val thread = Thread {
    try {
        val url = URL("https://httpbin.org/post")
        val httpURLConnection = url.openConnection() as HttpURLConnection
        httpURLConnection.requestMethod = "POST"
        httpURLConnection.doOutput = true
        httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

        // Creating POST data from the SENSITIVE_DATA map
        val postData = SENSITIVE_DATA.map { (key, value) ->
            "${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
        }.joinToString("&")

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
