package sg.vantagepoint.mstgkotlin

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import org.jetbrains.anko.find
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.android.core.Json
import com.github.kittinunf.fuel.android.extension.responseJson
import com.github.kittinunf.fuel.core.FuelError
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.Request
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.result.Result
import kotlinx.android.synthetic.main.activity_register.*
import org.jetbrains.anko.toast
import android.widget.Toast
import android.util.Patterns
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import com.github.kittinunf.fuel.httpPost
import org.jetbrains.anko.longToast

class RegisterActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_register)

        val username = find<EditText>(R.id.etusername)
        val email = find<EditText>(R.id.etemail)
        val password = find<EditText>(R.id.etpassword)
        val cpassword = find<EditText>(R.id.etconfirmpassword)
        val btnreset = find<Button>(R.id.btnreset)
        val btnsubmit = find<Button>(R.id.btnsubmit)
        val progressbar = find<ProgressBar>(R.id.progressBar)

        btnreset.setOnClickListener {
            username.setText("")
            email.setText("")
            password.setText("")
            cpassword.setText("")
            toast("Form cleared!")
        }

        btnsubmit.setOnClickListener {
            FuelManager.instance.basePath = "http://52.221.247.56"
            val loginurl = "/signup"
            val loginbody = "{ \"name\" : \"${username.text}\", \"email\" : \"${email.text}\", \"password\" : \"${password.text}\" }"

            if(validate(email.text, password.text, cpassword.text)) {
                // make progressbar visible
                progressbar.visibility = View.VISIBLE
                val req = Fuel.post(loginurl).body(loginbody)
                req.headers["Content-Type"] = "application/json"
                req.responseJson() { request, response, result ->
                    when (result) {
                        result.fold(success = { json ->
                            //longToast(json.array().toString())
                            //Log.d("request", request.toString())
                            //Log.d("response", response.toString())
                            //Log.d("result", response.toString())
                            longToast("New account has been created")
                        }, failure = { error ->
                            longToast("Something has went wrong, please try again later")
                        }) -> Unit
                    }
                    // remove progressbar after activity is completed
                    progressbar.visibility = View.GONE
                }
            } else {
                // no need to do anything ...
            }
        }
    }

    private fun validate(email: CharSequence, password: CharSequence, cpassword: CharSequence ): Boolean {
        var result = true
        if (!isValidEmail(email)) {
            toast("Invalid email address")
            result = false
        } else if (!isMatchingPassword(password,cpassword)) {
            toast("Password and confirm password don't match")
            result = false
        }
        return result
    }

    fun isValidEmail(target: CharSequence): Boolean {
        return !TextUtils.isEmpty(target) && Patterns.EMAIL_ADDRESS.matcher(target).matches()
    }

    fun isMatchingPassword(target1: CharSequence, target2: CharSequence): Boolean {
        return !TextUtils.isEmpty(target1) && !TextUtils.isEmpty(target2) && target1.toString().equals(target2.toString())
    }

}
