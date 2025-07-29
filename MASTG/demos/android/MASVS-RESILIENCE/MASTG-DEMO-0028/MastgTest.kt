package org.owasp.mastestapp

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.os.Build

class MastgTest(private val context: Context) {
    fun mastgTest(): String {
        val isLocked = isDeviceSecure(context)
        val biometricStatus = checkStrongBiometricStatus()
        return "Device has a passcode: $isLocked\n\n" +
                "Biometric status: $biometricStatus"
    }

    /**
     * Checks if the device has a secure lock screen (e.g., PIN, pattern, password).
     *
     * @return `true` if the device has a secure lock screen, `false` otherwise.
     */

    fun isDeviceSecure(context: Context): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    /**
     * Checks if the device supports strong biometric authentication (e.g., fingerprint, face, iris)
     * and if the user has enrolled biometric credentials.
     *
     * **Note:** This API is available on API level 30 (Android R) and above.
     *
     * @return A human-readable string describing the biometric status.
     */
    fun checkStrongBiometricStatus(): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val biometricManager = context.getSystemService(BiometricManager::class.java)
            val result = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            return when (result) {
                BiometricManager.BIOMETRIC_SUCCESS ->
                    "BIOMETRIC_SUCCESS - Strong biometric authentication is available."
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                    "BIOMETRIC_ERROR_NO_HARDWARE - No biometric hardware available."
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                    "BIOMETRIC_ERROR_HW_UNAVAILABLE - Biometric hardware is currently unavailable."
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                    "BIOMETRIC_ERROR_NONE_ENROLLED - No biometrics enrolled."
                else ->
                    "Unknown biometric status: $result"
            }
        } else {
            return "Strong biometric authentication check is not supported on this API level."
        }
    }
}
