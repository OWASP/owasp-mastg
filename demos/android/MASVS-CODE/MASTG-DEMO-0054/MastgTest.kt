package org.owasp.mastestapp

import android.content.Context
import android.os.Parcel
import android.os.Parcelable
import android.util.Log

class MastgTest(private val context: Context) {

    // Custom Parcelable class that can be abused
    class UserData(var username: String?, var isAdmin: Boolean) : Parcelable {

        constructor(parcel: Parcel) : this(
            parcel.readString(),
            parcel.readByte() != 0.toByte()
        )

        override fun writeToParcel(parcel: Parcel, flags: Int) {
            parcel.writeString(username)
            parcel.writeByte(if (isAdmin) 1 else 0)
        }

        override fun describeContents(): Int = 0

        companion object CREATOR : Parcelable.Creator<UserData> {
            override fun createFromParcel(parcel: Parcel): UserData {
                return UserData(parcel)
            }

            override fun newArray(size: Int): Array<UserData?> {
                return arrayOfNulls(size)
            }
        }
    }

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        // Simulate a malicious Parcel being deserialized
        val parcel = Parcel.obtain()
        parcel.writeString("attacker")   // fake username
        parcel.writeByte(1)              // isAdmin = true (malicious intent)
        parcel.setDataPosition(0)        // Reset pointer to start for reading

        val userData = UserData.CREATOR.createFromParcel(parcel)
        parcel.recycle()

        val result = "Deserialized User -> Username: ${userData.username}, isAdmin: ${userData.isAdmin}"
        Log.d("MASTG-TEST", result)

        return result
    }
}
