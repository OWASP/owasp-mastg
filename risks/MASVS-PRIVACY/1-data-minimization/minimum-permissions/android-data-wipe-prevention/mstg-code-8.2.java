public class StaticReferenceLeakActivity extends AppCompatActivity {
    // ruleid: MSTG-CODE-8.2
    private static TextView textView;
    // ruleid: MSTG-CODE-8.2
    private static Activity activity;
    // ok: MSTG-CODE-8.2
    private static String a;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_first);
        
        textView = findViewById(R.id.activity_text);
        textView.setText("Bad Idea!");
           
        activity = this;
    }
}
