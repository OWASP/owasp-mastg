public class MainActivity extends AppCompatActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        test();
    }
    private void test(){
        // ruleid: MSTG-STORAGE-2
      SharedPreferences sp = getContext().getSharedPreferences(OLD_PREFS_NAME, 2);
      int a = 3;
      String s = sp.getString("pwd", "not found");
    }
    public void test2(){
        // ruleid: MSTG-STORAGE-2
        FileOutputStream fos = openFileOutput(FILENAME, 2);
        fos.write(string.getBytes());
        fos.close();
    }
    public void test3(){
        File temp = File.createTempFile("FileBackedOutputStream", null);

        FileOutputStream transfer = new FileOutputStream(temp);
        transfer.write(memory.getBuffer(), 0, memory.getCount());
        transfer.flush();
    }
    public void test4(){
        File file = new File(context.getFilesDir(), "secret_data");
        EncryptedFile encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build();

        FileOutputStream encryptedOutputStream = encryptedFile.openFileOutput();

        FileInputStream encryptedInputStream = encryptedFile.openFileInput();
    }
    public void test5(){
        MasterKey masterKey = new MasterKey.Builder(context)
     .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
     .build();

        SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
            context,
            "secret_shared_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        // use the shared preferences and editor as you normally would
        SharedPreferences.Editor editor = sharedPreferences.edit();
    }
    public void test6(){
        // ruleid: MSTG-STORAGE-2
        File outFile = new File(ctx.getExternalFilesDir(null), filename);
        
    }
    public void test7(){
        SQLiteDatabase database = dbHelper.getWritableDatabase();
        ContentValues testValues = new ContentValues();
        testValues.put(WaitlistContract.WaitlistEntry.COLUMN_GUEST_NAME, "test name");
        testValues.put(WaitlistContract.WaitlistEntry.COLUMN_PARTY_SIZE, 99);
        long firstRowId = database.insert(
            WaitlistContract.WaitlistEntry.TABLE_NAME,
            null,
            testValues);
        // ruleid: MSTG-STORAGE-2
        Cursor c = database.rawQuery("tab_secret", tableColumns, whereClause, whereArgs, null, null, orderBy);
    }
    public void test8(){
        // ruleid: MSTG-STORAGE-2
        SharedPreferences sharedPref = context.getSharedPreferences(
        getString(R.string.preference_file_key), 1);
    }
}
