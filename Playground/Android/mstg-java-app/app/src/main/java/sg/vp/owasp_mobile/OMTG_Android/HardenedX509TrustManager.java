package sg.vp.owasp_mobile.OMTG_Android;

import android.util.Log;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * Created by sven on 11/4/17.
 */


public class HardenedX509TrustManager<E>
        implements X509TrustManager {

    private X509TrustManager standardTrustManager = null;
    // Change this to the authority you want to pin the certificate into
    public static final String TRUSTED_CA_AUTHORITY = "PortSwigger";

    /**
     * Constructor for EasyX509TrustManager.
     */
    public HardenedX509TrustManager( KeyStore keystore )
            throws NoSuchAlgorithmException, KeyStoreException
    {
        super();
        TrustManagerFactory factory = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
        factory.init( keystore );
        TrustManager[] trustmanagers = factory.getTrustManagers();
        if ( trustmanagers.length == 0 )
        {
            throw new NoSuchAlgorithmException( "no trust manager found" );
        }
        this.standardTrustManager = (X509TrustManager) trustmanagers[0];
    }

    /**
    // * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],String authType)
     */
    public void checkClientTrusted( X509Certificate[] certificates, String authType )
            throws CertificateException
    {
        standardTrustManager.checkClientTrusted( certificates, authType );
    }

    /**
//     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],String authType)
     */
    public void checkServerTrusted( X509Certificate[] certificates, String authType )
            throws CertificateException
    {
        standardTrustManager.checkServerTrusted( certificates, authType );

        for (X509Certificate cert : certificates) {
            String issuer_name = cert.getIssuerDN().getName();
            if (issuer_name.indexOf(",O=" + TRUSTED_CA_AUTHORITY + ",") == -1)
                throw new CertificateException();
            Log.w("Error", issuer_name);
        }
    }

    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers()
    {
        X509Certificate[] test = this.standardTrustManager.getAcceptedIssuers();
        return test;
        //return this.standardTrustManager.getAcceptedIssuers();
    }

}
