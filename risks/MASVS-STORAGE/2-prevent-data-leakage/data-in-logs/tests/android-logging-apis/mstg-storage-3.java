import java.io.BufferedWriter;
import java.util.logging.Logger;

public class MainActivity extends AppCompatActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // ruleid: MSTG-STORAGE-3
        Log.v("tag", "key: " + variable);
        // ruleid: MSTG-STORAGE-3
        Log.i("tag", "key: " + password_secret_key + sec);
        // ruleid: MSTG-STORAGE-3
        Log.w("tag", "test: " + IV);
        Log.d("tag", "test: " + iv);
        Log.e("tag", "test: " + variable);
        // ok: MSTG-STORAGE-3
        Log.wtf("tag", "test: " + variable);
        // ruleid: MSTG-STORAGE-3
        System.out.print("key");
        // ruleid: MSTG-STORAGE-3
        System.err.print("key");

        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new
        FileOutputStream(FileDescriptor.out), "ASCII"), 512);
        // ruleid: MSTG-STORAGE-3
        out.write("key string");
        out.write('\n');
        out.flush();

        Logger x = new Logger();
        // ruleid: MSTG-STORAGE-3
        x.severe("key");
    }
}
