package sg.vantagepoint.mstgkotlin

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import kotlinx.android.synthetic.main.activity_menu.*
import kotlinx.android.synthetic.main.activity_menu.view.*
import org.jetbrains.anko.find
import org.jetbrains.anko.longToast
import org.jetbrains.anko.startActivity
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class MenuActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_menu)

        // flags for tracking the toggle mode for details view
        var flag_sharedPref = false
        var flag_webview = false
        var flag_rootcheck = false

        // variables to control the elements on the layout
        val tv_sharedPref = find<TextView>(R.id.tvsharedpref)
        val tv_sharedPrefDetails = find<TextView>(R.id.tvsharedpref_details)
        val tv_webview = find<TextView>(R.id.tvwebview)
        val tv_webviewDetails = find<TextView>(R.id.tvwebview_details)
        val tv_rootcheck = find<TextView>(R.id.tvrootcheck)
        val tv_rootcheckDetails = find<TextView>(R.id.tvrootcheck_details)
        val btn_unsafeWebview = find<Button>(R.id.btn_unsafe_webview)
        val btn_safeWebview = find<Button>(R.id.btn_safe_webview)
        val btn_insecureRootCheck = find<Button>(R.id.btn_insecure_rootcheck)
        val btn_secureRootCheck = find<Button>(R.id.btn_secure_rootcheck)

        // handle the sharedpreference option
        tv_sharedPref.setOnClickListener {
            flag_sharedPref = toggleFlag(flag_sharedPref, tv_sharedPrefDetails)
        }

        // handle the webview option
        tv_webview.setOnClickListener {
            flag_webview = toggleFlag(flag_webview, tv_webviewDetails)
            if(flag_webview==true){
                btn_unsafeWebview.visibility = View.VISIBLE
                btn_safeWebview.visibility = View.VISIBLE
            } else {
                btn_unsafeWebview.visibility = View.GONE
                btn_safeWebview.visibility = View.GONE
            }

        }

        // handle the rootcheck option
        tv_rootcheck.setOnClickListener {
            flag_rootcheck = toggleFlag(flag_rootcheck, tv_rootcheckDetails)
            if(flag_rootcheck==true){
                btn_insecure_rootcheck.visibility = View.VISIBLE
                btn_secure_rootcheck.visibility = View.VISIBLE
            } else {
                btn_insecure_rootcheck.visibility = View.GONE
                btn_secure_rootcheck.visibility = View.GONE
            }
//            Log.d("Checkpoint","clicked on rootcheck")
        }

        // handle the action of switching to the secureWebViewActivity when user selects it
        btn_safeWebview.setOnClickListener{
            goToSecureWebViewActivity()
        }

        // handle the action of switching to the secureWebViewActivity when user selects it
        btn_unsafeWebview.setOnClickListener{
            goToInsecureWebViewActivity()
        }

        // handle the secure implementation function of root detection
        btn_secureRootCheck.setOnClickListener{
            // using 4 different methods to perform the check, therefore secure implementation
            if(isDeviceRooted()==true) {
                longToast("Device is rooted!")
            } else {
                longToast("Device is NOT rooted!")
            }
        }

        // handle the insecure implementation function of root detection
        btn_insecureRootCheck.setOnClickListener {
            // only one method to check, incomplete and therefore insecure implementation
            if(insecureCheckRootMethod()==true) {
                longToast("Device is rooted!")
            } else {
                longToast("Device is NOT rooted!")
            }
        }

    }

    fun toggleFlag(flag: Boolean, tv: TextView): Boolean {
        if(flag==false) {
            tv.visibility = View.VISIBLE
            return true
        } else {
            tv.visibility = View.GONE
            return false
        }
    }

    private fun goToSecureWebViewActivity() {
//        Log.d("Checkpoint","goToSecureWebViewActivity()")
        startActivity<SecureWebViewActivity>()
    }

    private fun goToInsecureWebViewActivity() {
        startActivity<InsecureWebViewActivity>()
    }

    // the following methods are for root detection: isDeviceRooted(), checkRootMethod1(), checkRootMethod2(), checkRootMethod3()
    fun isDeviceRooted(): Boolean {
        return (checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4())
    }

    private fun checkRootMethod1(): Boolean {
        val buildTags = android.os.Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootMethod2(): Boolean {
        val paths = arrayOf("/system/app/Superuser.apk","/system/etc/init.d/99SuperSUDaemon","/dev/com.koushikdutta.superuser.daemon/","/system/xbin/daemonsu", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su")
        for (path in paths) {
            if (File(path).exists()) return true
        }
        return false
    }

    private fun checkRootMethod3(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val `in` = BufferedReader(InputStreamReader(process?.inputStream))
            return if (`in`.readLine() != null) true else false
        } catch (t: Throwable) {
            return false
        } finally {
            if (process != null) process.destroy()
        }
    }

    private fun checkRootMethod4(): Boolean {
        for (pathDir in System.getenv("PATH").split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()) {
            if (File(pathDir, "su").exists()) {
                return true
            }
        }
        return false
    }

    private fun insecureCheckRootMethod(): Boolean {
        val paths = arrayOf("/system/bin/su")
        for (path in paths) {
            if (File(path).exists()) return true
        }
        return false
    }
}
