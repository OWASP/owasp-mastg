package sg.vp.owasp_mobile.OMTG_Android;



import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * Created by sven on 11/4/17.
 */
public class SSLPinning {


//    @Override
    public void onCreate() {

        // This must be performed once at the start of the application to install required handlers
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            // Use our hardend version
            ctx.init(null, new TrustManager[]{new HardenedX509TrustManager(null)}, null);
            // Set the default SSL Factory of the application to the new instance we have created
            // All HTTPS / SSL access libraries will now use our new class instead of the system
            // default
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        } catch (NoSuchAlgorithmException e) {
            // Log or handle the exception accordingly
            // We exit here for safety reason as the certificate pinning mechanism is not enabled
            System.exit(-1);
        } catch (KeyManagementException e) {
            // Log or handle the exception accordingly
            // We exit here for safety reason as the certificate pinning mechanism is not enabled
            System.exit(-1);
        } catch (KeyStoreException e) {
            // Log or handle the exception accordingly
            // We exit here for safety reason as the certificate pinning mechanism is not enabled
            System.exit(-1);
        }

    }
}
