// InsecureStorageDemo.java
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

public class InsecureStorageDemo extends Context {
    public void insecureDataStorageMethod() {
        SharedPreferences prefs = getSharedPreferences("user_prefs", MODE_PRIVATE);
        // Insecurely storing sensitive data in SharedPreferences without encryption
        prefs.edit().putString("authToken", "123456789").apply();
        
        // Attempting to store data in external storage without encryption
        try {
            File externalStorage = Environment.getExternalStorageDirectory();
            File myFile = new File(externalStorage, "sensitiveData.txt");
            FileOutputStream fos = new FileOutputStream(myFile);
            OutputStreamWriter osw = new OutputStreamWriter(fos);
            osw.write("Sensitive information, like passwords or personal info.");
            osw.close();
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
