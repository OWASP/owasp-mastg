public class MainActivity extends AppCompatActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        test();
    }
    private void test(){
        EditText edtView=(EditText)findViewById(R.id.editTextConvertValue);
        edtView.setInputType(0);
        editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);

        EditText key=(EditText)findViewById(R.id.editTextConvertValue);
        // ruleid: MSTG-STORAGE-5.2
        key.setInputType(0);
        key.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);

        EditText abc=(EditText)findViewById(R.id.editTextConvertpwdValue);
        // ruleid: MSTG-STORAGE-5.2
        abc.setInputType(InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);

        EditText abc=(EditText)findViewById(R.id.editTextConvertpwdValue);
        // ok: MSTG-STORAGE-5.2
        abc.setInputType(0x00080000);

        EditText abc=(EditText)findViewById(R.id.editTextConvertpwdValue);
        // ok: MSTG-STORAGE-5.2
        abc.setInputType(524288);

    }
}
