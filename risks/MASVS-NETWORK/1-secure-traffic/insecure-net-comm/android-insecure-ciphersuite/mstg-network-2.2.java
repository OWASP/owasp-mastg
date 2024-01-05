public class MainActivity extends AppCompatActivity {
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        // unrecommended cipher added via array static initialization
        String[] weakCiphers = {"SSL_RSA_WITH_RC4_128_MD5"};
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ruleid: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(weakCiphers);
		return s;
    }
    
    public Socket createSocket1(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        String[] a = new String[2];
        for (int i=0;i < a.length; i++) {
            // unrecommended cipher added via string array
            a[i] = "SSL_RSA_WITH_RC4_128_MD5";
        }
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ruleid: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(a);
		return s;
    }

    public Socket createSocket2(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        ArrayList<String> weakCiphers = new ArrayList<>();
        // unrecommended cipher added via arrayList.add()
        weakCiphers.add("SSL_RSA_WITH_RC4_128_MD5");
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ruleid: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(weakCiphers.toArray());
		return s;
    }

    public Socket createSocket3(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        ArrayList<String> mixCiphers = new ArrayList<>();
        // mixed ciphers added via arrayList.addAll()
        String[] mixedStrenghtCiphers = {
            // unrecommended
            "SSL_RSA_WITH_RC4_128_MD5",
            // recommended
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        };
        mixCiphers.addAll(mixedStrenghtCiphers);
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ruleid: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(mixCiphers.toArray());
		return s;
    }

    public Socket createSocket4(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        ArrayList<String> weakCiphers = new ArrayList<>();
        String[] b = new String[2];
        for (int i=0;i < a.length; i++) {
            // recommended cipher added via string array
            b[i] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        }
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ok: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(b);
		return s;
    }

    public Socket createSocket5(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
        ArrayList<String> strongCiphers = new ArrayList<>();
        // recommended cipher added via arrayList.add()
        strongCiphers.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
		if (g_IOException != null)
			throw g_IOException;
		SSLSocket s = (SSLSocket)g_factory.createSocket(address, port, localAddress, localPort);
        // ok: MSTG-NETWORK-2.2
		s.setEnabledCipherSuites(strongCiphers);
		return s;
    }
}
