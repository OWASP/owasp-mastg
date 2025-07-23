package org.owasp.mastestapp

import android.content.Intent
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.io.Serializable
import java.util.Base64


object UserManager {

    var currentUser: MastgTest.BaseUser = MastgTest.BaseUser("Standard User")
}

class MastgTest {

    open class BaseUser(val username: String) : Serializable {
        companion object {
            private const val serialVersionUID = 100L
        }
    }

    class AdminUser(username: String) : BaseUser(username) {

        var isAdmin: Boolean = false

        companion object {
            private const val serialVersionUID = 200L
        }
    }

    fun mastgTest(): String {
        val user = UserManager.currentUser
        val status = if (user is AdminUser && user.isAdmin) {
            "PRIVILEGED ADMIN!"
        } else {
            "(Not an Admin)"
        }

        val resultString = "Current User: ${user.username}\n" +
                "Status: $status\n\n" +
                "Vulnerability: Unwanted Object Deserialization is active.\n" +
                "The app will deserialize any 'BaseUser' subclass from the 'payload_b64' extra, " +
                "overwriting the current user state."

        Log.d("MASTG-TEST", resultString)
        return resultString
    }

    fun processIntent(intent: Intent) {
        if (intent.hasExtra("payload_b64")) {
            val b64Payload = intent.getStringExtra("payload_b64")
            Log.d("VULN_APP", "Received a base64 payload. Deserializing user object...")

            try {
                val serializedPayload = Base64.getDecoder().decode(b64Payload)
                val ois = ObjectInputStream(ByteArrayInputStream(serializedPayload))
                val untrustedObject = ois.readObject()
                ois.close()

                if (untrustedObject is BaseUser) {
                    UserManager.currentUser = untrustedObject
                    Log.i("VULN_APP", "User state overwritten with deserialized object!")
                } else {
                    Log.w("VULN_APP", "Deserialized object was not a user. State unchanged.")
                }

            } catch (e: Exception) {
                Log.e("VULN_APP", "Failed to deserialize payload", e)
            }
        }
    }
}
