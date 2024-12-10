package org.owasp.mastestapp


import android.content.Context
import android.util.Log


// mock: freeRASP ThreatDetected interface
interface ThreatDetected {
    fun onRootDetected()
    fun onDebuggerDetected()
    fun onEmulatorDetected()
    fun onTamperDetected()
    fun onUntrustedInstallationSourceDetected()
    fun onHookDetected()
    fun onDeviceBindingDetected()
    fun onObfuscationIssuesDetected()
}


// MastgTest class implementing ThreatDetected
class MastgTest(private val context: Context) : ThreatDetected {


    companion object {
        const val FREERASP_THREAT_TAG = "freeRASP Threat: "
    }


    fun mastgTest(): String {
        return simulateThreatDetection()
    }


    // Simulate a test by calling onRootDetected
    fun simulateThreatDetection() : String {
        onRootDetected() // mock root was detected by freeRASP


        return "freeRASP Threat:  onRootDetected"
    }


    fun closeApp() {
        // finishAffinity() // Closes all screens of the app
        // System.exit(0) // Completely exits the app process
    }




    override fun onRootDetected() {
        Log.d(FREERASP_THREAT_TAG, "onRootDetected")
        closeApp() // Standard method to forcefully terminate the app
    }


    override fun onDebuggerDetected() {
        Log.d(FREERASP_THREAT_TAG, "onDebuggerDetected")
    }


    override fun onEmulatorDetected() {
        Log.d(FREERASP_THREAT_TAG, "onEmulatorDetected")
    }


    override fun onTamperDetected() {
        Log.d(FREERASP_THREAT_TAG, "onTamperDetected")
    }


    override fun onUntrustedInstallationSourceDetected() {
        Log.d(FREERASP_THREAT_TAG, "onUntrustedInstallationSourceDetected")
    }


    override fun onHookDetected() {
        Log.d(FREERASP_THREAT_TAG, "onHookDetected")
    }


    override fun onDeviceBindingDetected() {
        Log.d(FREERASP_THREAT_TAG, "onDeviceBindingDetected")
    }


    override fun onObfuscationIssuesDetected() {
        Log.d(FREERASP_THREAT_TAG, "onObfuscationIssuesDetected")
    }
}
