// On lower Android verions, you might need to add `WRITE_EXTERNAL_STORAGE` permission to the manifest to write to an external app-specific directory.

val externalDirPath = getExternalFilesDir(null)!!.absolutePath
val file: File = File("$externalDirPath/secret.json")
FileOutputStream(file).use { fos ->
    fos.write("password:123".toByteArray())
}
