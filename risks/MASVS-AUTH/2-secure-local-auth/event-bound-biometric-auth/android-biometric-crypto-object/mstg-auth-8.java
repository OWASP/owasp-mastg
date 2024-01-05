import androidx.biometric.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.fingerprint.FingerprintManagerCompat;

public class MainActivity extends AppCompatActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        test_vulnBiometricPrompt();
        test_vulnFingerprintManager();
        test_vulnFingerprintManagerCompat();
        test_goodBiometricPrompt();
    }

    private void test_vulnBiometricPrompt() {
        // Vulnerable BiometricPrompt
        //[...]
        biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            // ruleid: MSTG-AUTH-8
            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                //Does not use the CryptoObject from result
                Toast.makeText(MainActivity.this,"Success",Toast.LENGTH_LONG).show();
                setContentView(R.layout.fingerprint_normal);
            }

            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this,errString,Toast.LENGTH_LONG).show();
                MainActivity.this.finish();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this,"FAILED",Toast.LENGTH_LONG).show();
            }
        });
    }

    // Vulnerable FingerprintManager
    //[...]
        public void Authentication(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {
            CancellationSignal cancellationSignal = new CancellationSignal();
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
        }
  
        @Override
        public void onAuthenticationFailed() {
            this.update("Authentication Failed!!!", false);
        }
        // ruleid: MSTG-AUTH-8
        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            //Does not use the CryptoObject from result
            this.update("Successfully Authenticated...", true);
        }

        public void update(String e, Boolean success){
            TextView textView = (TextView) ((Activity)context).findViewById(R.id.textMsg);
            textView.setText(e);
            if(success){
                textView.setTextColor(ContextCompat.getColor(context,R.color.black));
            }
        }
    //[...]
    
    private void test_vulnFingerprintManagerCompat() {
        // Vulnerable FingerprintManagerCompat
        //[...]
        fingerprintManager.authenticate(null, 0, cancellationSignal, new FingerprintManagerCompat.AuthenticationCallback() {

            @Override
            public void onAuthenticationError(int errMsgId, CharSequence errString) {
                if (!selfCancelled) {
                    showFingerprintError(errString);
                }
            }

            @Override
            public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                showFingerprintError(helpString);
            }

            @Override
            public void onAuthenticationFailed() {
                showFingerprintError(LocaleController.getString("FingerprintNotRecognized",
                        R.string.FingerprintNotRecognized));
            }
            // ruleid: MSTG-AUTH-8
            @Override
            public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                try {
                    //Does not use the CryptoObject from result
                    if (fingerprintDialog.isShowing()) {
                        fingerprintDialog.dismiss();
                    }
                } catch (Exception e) {
                    FileLog.e("messenger", e);
                }
                fingerprintDialog = null;
                processDone(true);
            }
        }, null);
    }

    private void test_goodBiometricPrompt() {
        // Good BiometricPrompt
        //[...]
        biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            // ok: MSTG-AUTH-8
            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                //Uses the CryptoObject from result
                if (result.getCryptoObject() != null &&
                        result.getCryptoObject().getCrypto() != null) {
                    try {
                        Cipher cipher = result.getCryptoObject().getCipher();
                        byte[] decrypted = cipher.doFinal(encrypted);
                        //[...]
                    } catch (CipherException e) {
                        throw new RuntimeException();
                    }
                } else {
                    // Error handling
                }
            }

            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this,errString,Toast.LENGTH_LONG).show();
                MainActivity.this.finish();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this,"FAILED",Toast.LENGTH_LONG).show();
            }
        });
    }
}
