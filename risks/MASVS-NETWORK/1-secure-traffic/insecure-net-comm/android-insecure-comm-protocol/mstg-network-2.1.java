public class MainActivity extends AppCompatActivity {

    private SSLSocketFactory defaultSslSocketFactory(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ok: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory defaultSslSocketFactory1(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("TLSv1.1");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory defaultSslSocketFactory2(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory defaultSslSocketFactory3(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ok: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory defaultSslSocketFactory4(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory defaultSslSocketFactory5(X509TrustManager trustManager)
    throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: MSTG-NETWORK-2.1
        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext.getSocketFactory();
    }
}
