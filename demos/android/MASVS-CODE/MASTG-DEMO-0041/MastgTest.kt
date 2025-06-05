package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable

class MastgTest(private val context: Context) {

    // Serializable class (normally would contain business logic)
    class UserData(val username: String, val isAdmin: Boolean) : Serializable

    fun mastgTest(): String {
        val fileName = "userdata.ser"
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        try {
            // Step 1: Serialize UserData object
            val user = UserData("alice", false)
            val fileOutput = context.openFileOutput(fileName, Context.MODE_PRIVATE)
            val objectOutput = ObjectOutputStream(fileOutput)
            objectOutput.writeObject(user)
            objectOutput.close()
            fileOutput.close()
            Log.d("MASTG-TEST", "UserData object serialized")

            // Step 2: Deserialize the object (simulate untrusted input later)
            val fileInput = context.openFileInput(fileName)
            val objectInput = ObjectInputStream(fileInput)
            val deserializedUser = objectInput.readObject() as UserData
            objectInput.close()
            fileInput.close()
            Log.d("MASTG-TEST", "Deserialized username: ${deserializedUser.username}")
            Log.d("MASTG-TEST", "Is Admin: ${deserializedUser.isAdmin}")

            return "Deserialized user: ${deserializedUser.username}, isAdmin=${deserializedUser.isAdmin}"

        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Deserialization error: ${e.message}")
            return "Error during deserialization: ${e.message}"
        }
    }
}
