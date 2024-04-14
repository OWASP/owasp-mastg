import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

public class InsecureStorageDemo extends Context {
    public void insecureDataStorageMethod() {
        // Insecurely storing sensitive data in SharedPreferences without encryption
        SharedPreferences prefs = getSharedPreferences("user_prefs", MODE_PRIVATE);
        prefs.edit().putString("authToken", "123456789").apply();
        prefs.edit().putString("password", "userPassword123").apply(); // Additional pattern

        // Attempting to store data in external storage without encryption
        try {
            File externalStorage = Environment.getExternalStorageDirectory();
            File sensitiveFile = new File(externalStorage, "sensitiveData.txt");
            FileOutputStream fos = new FileOutputStream(sensitiveFile);
            OutputStreamWriter osw = new OutputStreamWriter(fos);
            osw.write("Sensitive information, like passwords or personal info.");
            osw.close();
            fos.close();

            // Additional insecure data write to external storage
            FileOutputStream fos2 = new FileOutputStream(new File(externalStorage, "userData.txt"));
            osw = new OutputStreamWriter(fos2);
            osw.write("Usernames, email addresses, and other personal data.");
            osw.close();
            fos2.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
