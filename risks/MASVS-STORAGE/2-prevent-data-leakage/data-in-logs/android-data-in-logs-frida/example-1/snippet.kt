package org.owasp.mastg.logging

import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import com.google.android.material.snackbar.Snackbar
import org.owasp.mastg.logging.databinding.ActivityMainBinding
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.BufferedWriter
import java.util.logging.Logger


class MainActivity : AppCompatActivity() {

    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)

        val navController = findNavController(R.id.nav_host_fragment_content_main)
        appBarConfiguration = AppBarConfiguration(navController.graph)
        setupActionBarWithNavController(navController, appBarConfiguration)

        binding.fab.setOnClickListener {

            val myVariable = "Logging test!"
            logVariableTest("Frida-Logging-Test", "myVariable", myVariable)
        }
    }

    private val logger = Logger.getLogger(MainActivity::class.java.name)

    fun logVariableTest(tag: String, key: String, variable: Any) {

        // define test data
        var password_secret_key = "1234"
        var sec = "5678"
        var IV = ""
        var iv = ""

        // ruleid: MSTG-STORAGE-3
        Log.v(tag, "$key: $variable")

        // ruleid: MSTG-STORAGE-3
        Log.i("tag", "key: $password_secret_key$sec")

        // ruleid: MSTG-STORAGE-3
        Log.w("tag", "test: $IV")
        Log.d("tag", "test: $iv")
        Log.e("tag", "test: $variable")

        // ok: MSTG-STORAGE-3
        Log.wtf("tag", "test: $variable")

        // ruleid: MSTG-STORAGE-3
        print("key")

        // ruleid: MSTG-STORAGE-3
        System.err.print("key")

        val out =
            BufferedWriter(OutputStreamWriter(FileOutputStream(FileDescriptor.out), "ASCII"), 512)
        // ruleid: MSTG-STORAGE-3
        // ruleid: MSTG-STORAGE-3
        out.write("key string")
        out.write('\n'.code)
        out.flush()

        // ruleid: MSTG-STORAGE-3
        logger.severe("key")

    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment_content_main)
        return navController.navigateUp(appBarConfiguration)
                || super.onSupportNavigateUp()
    }
}