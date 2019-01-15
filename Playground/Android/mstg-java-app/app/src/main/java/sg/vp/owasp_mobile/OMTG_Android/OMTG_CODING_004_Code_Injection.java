package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;



// Sample from  http://stackoverflow.com/questions/6857807/is-it-possible-to-dynamically-load-a-library-at-runtime-from-an-android-applicat
public class OMTG_CODING_004_Code_Injection extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__coding_004__code__injection);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        try {
            final String libPath = Environment.getExternalStorageDirectory() + "/libcodeinjection.jar";
            final File tmpDir = getDir("dex", 0);

//            Log.e("Directory getExternalStorageDirectory: ", Environment.getExternalStorageDirectory().toString());

            final DexClassLoader classloader = new DexClassLoader(libPath, tmpDir.getAbsolutePath(), null, this.getClass().getClassLoader());
            final Class<Object> classToLoad = (Class<Object>) classloader.loadClass("com.example.CodeInjection");

//            Log.e("Directory tmpDir: ", tmpDir.getAbsolutePath().toString());

            final Object myInstance  = classToLoad.newInstance();
            final Method returnString = classToLoad.getMethod("returnString");

            String result = (String) returnString.invoke(myInstance);

            Log.e("Test", result);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
