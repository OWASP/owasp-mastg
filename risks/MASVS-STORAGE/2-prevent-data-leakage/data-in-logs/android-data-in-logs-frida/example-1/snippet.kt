val variable = "MAS-Sensitive-Value"
val password = "MAS-Sensitive-Password"
val secret_key = "MAS-Sensitive-Key"
val IV = "MAS-Sensitive-Value-IV"
val iv = "MAS-Sensitive-Value-IV-2"

Log.v("MASTG", "key: $variable")
Log.i("MASTG", "key: $password")
Log.w("MASTG", "test: $IV")
Log.d("MASTG", "test: $iv")
Log.e("MASTG", "test: $variable")
Log.wtf("MASTG", "test: $variable")

val x = Logger.getLogger("myLogger")
x.severe(secret_key)
