object RootDetector {
   fun isDeviceRooted(): Boolean {
       return checkRootFiles() || checkSuperUserApk() || checkSuCommand()
   }

   internal fun checkRootFiles(): Boolean {
       val rootPaths = listOf(
           "/system/app/Superuser.apk",
           "/system/xbin/su",
           "/system/bin/su",
           "/sbin/su",
           "/system/sd/xbin/su",
           "/system/bin/.ext/.su",
           "/system/usr/we-need-root/su-backup",
           "/system/xbin/mu"
       )
       rootPaths.forEach { path ->
           if (File(path).exists()) {
               Log.d("RootCheck", "Found root file: $path")
           }
       }
       return rootPaths.any { path -> File(path).exists() }
   }

   private fun checkSuperUserApk(): Boolean {
       val superUserApk = File("/system/app/Superuser.apk")
       if (superUserApk.exists()) {
           Log.d("RootCheck", "Found Superuser.apk")
       }
       return superUserApk.exists()
   }

   internal fun checkSuCommand(): Boolean {
       return try {
           val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
           val reader = BufferedReader(InputStreamReader(process.inputStream))
           val result = reader.readLine()
           if (result != null) {
               Log.d("RootCheck", "su command found at: $result")
               true
           } else {
               Log.d("RootCheck", "su command not found")
               false
           }
       } catch (e: IOException) {
           Log.d("RootCheck", "Error checking su command: ${e.message}")
           false
       }
   }
}
