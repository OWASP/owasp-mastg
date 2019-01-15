package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import sg.vp.owasp_mobile.OMTG_Android.R;

public class OMTG_NETW_004_SSL_Pinning_Certificate extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__netw_004__ssl__pinning__certificate);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        try {
            HTTPSssLPinning();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    private void HTTPSssLPinning() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {


        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Generate the certificate using the certificate file under res/raw/certificate
        InputStream caInput = new BufferedInputStream(getResources().openRawResource(R.raw.certificate));
        Certificate ca = cf.generateCertificate(caInput);
        caInput.close();

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);
        Enumeration keyStoreAlias = keyStore.aliases();
        while(keyStoreAlias.hasMoreElements())
            System.out.println("KeyStore: "+keyStoreAlias.nextElement().toString());


        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Create an SSLContext that uses our TrustManager
        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);

        // Tell the URLConnection to use a SocketFactory from our SSLContext
        // Quick and dirty fix http://stackoverflow.com/questions/6343166/how-to-fix-android-os-networkonmainthreadexception
        Thread thread = new Thread(new Runnable() {

            @Override
            public void run() {
                try {
                    URL url = null;
                    try {
                        url = new URL("https://example.com");
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    }
                    HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setSSLSocketFactory(context.getSocketFactory());
                    // Get response and print it to stdout
                    InputStream in = urlConnection.getInputStream();
                    InputStreamReader isr = new InputStreamReader(in);
                    BufferedReader br = new BufferedReader(isr);

                    String inputLine;

                    while ((inputLine = br.readLine()) != null) {
                        System.out.println(inputLine);
                    }

                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        thread.start();

    }




}
