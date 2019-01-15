package sg.vantagepoint.mstgkotlin

import android.content.SharedPreferences
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.text.TextUtils
import android.util.Log
import android.util.Patterns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.android.extension.responseJson
import com.github.kittinunf.fuel.core.FuelManager
import de.adorsys.android.securestoragelibrary.SecurePreferences
import org.jetbrains.anko.find
import org.jetbrains.anko.longToast
import org.jetbrains.anko.startActivity
import org.jetbrains.anko.toast

class MainActivity : AppCompatActivity() {

    // for storing JWT token after successful authentication
    var token = ""

    // file and objects for storing the SharedPreferences
    val jwtInsecureFilename = "InsecurePreferences"
    private var prefsInsecure: SharedPreferences? = null // this.getSharedPreferences(jwtInsecureFilename, 0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val loginemail = find<EditText>(R.id.etemail)
        val loginpassword = find<EditText>(R.id.etpassword)
        val btnregister = find<Button>(R.id.btnregister)
        val btnsubmit = find<Button>(R.id.btnsubmit)
        val progressbar = find<ProgressBar>(R.id.progressBar)

        btnregister.setOnClickListener {
            goToRegister()
        }

        btnsubmit.setOnClickListener {
            FuelManager.instance.basePath = "http://52.221.247.56"
            val loginurl = "/auth/login"
            val loginbody = "{ \"email\" : \"${loginemail.text}\", \"password\" : \"${loginpassword.text}\" }"

            if (isValidEmail(loginemail.text)) {
                // make progressbar visible
                progressbar.visibility = View.VISIBLE
                val req = Fuel.post(loginurl).body(loginbody)
                req.headers["Content-Type"] = "application/json"
                req.responseJson() { request, response, result ->
                    when (result) {
                        result.fold(success = { json ->
                            token = json.obj().getString("auth_token")
                            Log.d("token",json.obj().getString("auth_token"))
                        }, failure = { error ->
                            longToast("Invalid login credentials")
                        }) -> Unit
                    }
                    // remove progressbar after activity is completed
                    progressbar.visibility = View.GONE

                    if(!TextUtils.isEmpty(token)){
                        //longToast("token is not empty")
                        //longToast(token)

                        // storing the clear-text JWT in a SharedPreferences XML file
                        prefsInsecure = this.getSharedPreferences(jwtInsecureFilename, 0)
                        val editor_insecure = prefsInsecure?.edit()
                        editor_insecure?.putString("auth_token", token)
                        editor_insecure?.apply()

                        // storing the KeyStore encrypted JWT in a SharedPreferences XML file
                        SecurePreferences.setValue("auth_token",token,this)
                        //Log.d("SecurePreferences",SecurePreferences.getStringValue("auth_token",this,null))

                        // start activity and go to menu
                        goToMenu()

                    }
                }
            } else {
                longToast("Invalid email address format")
            }
        }
    }

    private fun goToRegister() {
        //longToast("inside goToRegister()")
        startActivity<RegisterActivity>()
    }

    fun isValidEmail(target: CharSequence): Boolean {
        return !TextUtils.isEmpty(target) && Patterns.EMAIL_ADDRESS.matcher(target).matches()
    }

    private fun goToMenu() {
        //longToast("inside goToMenu()")
        startActivity<MenuActivity>()
    }

}