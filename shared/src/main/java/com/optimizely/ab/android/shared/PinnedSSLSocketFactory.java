package com.optimizely.ab.android.shared;

import android.content.Context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class PinnedSSLSocketFactory {

    private Logger logger = LoggerFactory.getLogger(PinnedSSLSocketFactory.class);

    public enum Host {
        LOGX,
        CDN,
        API
    }

    private static final String EVENT_CERT_FILENAME = "DigiCertHighAssuranceEVRootCA.crt";
    private static final String DATAFILE_CERT_FILENAME = "DigiCertGlobalRootCA.crt";
    private static final String REST_API_CERT_FILENAME = "AmazonRootCA1.crt";

    public SSLSocketFactory getPinnedSslSocket(Context context, Host host) {
        InputStream certificate = null;
        switch (host){
            case LOGX:
                certificate = getCert(context, EVENT_CERT_FILENAME);
                break;
            case CDN:
                certificate = getCert(context, DATAFILE_CERT_FILENAME);
                break;
            case API:
                certificate = getCert(context, REST_API_CERT_FILENAME);
                break;
            default:
                break;
        }

        // Return null, if no certificate exists
        if (certificate != null) {
            logger.info("pinning the connection");
            return getSSLSocketFactory(certificate);
        } else {
            //fail safe
            logger.error("Failed to create sslsocketfactory for the certificate");
            return null;
        }
    }

    private InputStream getCert(Context context, String certFilename) {
        InputStream certificate = null;
        try {
            certificate = context.getAssets().open(certFilename);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return certificate;
    }

    /**
     * Creates a new SSLSocketFactory instance
     *
     * @param input InputStream with CA certificate.
     * @return The new SSLSocketFactory instance.
     *
     */
    private SSLSocketFactory getSSLSocketFactory(InputStream input) {
        try {

            // Load trusted CAs from the input stream - Could be from a resource or ByteArrayInputStream
            Certificate ca;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ca = cf.generateCertificate(input);
            logger.info("ca= " + ((X509Certificate) ca).getSubjectDN());
            input.close();

            // Create a KeyStore containing our trusted CAs
            KeyStore keyStore;
            String keyStoreType = KeyStore.getDefaultType();
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);

            // Create a TrustManager that trusts the CAs in our KeyStore
            TrustManager[] trustManagers;
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            trustManagers = tmf.getTrustManagers();

            // Create an SSLContext that uses our TrustManager
            SSLContext mSslContext = SSLContext.getInstance("TLS");
            mSslContext.init(null, trustManagers, null);

            // Return a SocketFactory object for the SSLContext
            return mSslContext.getSocketFactory();
        } catch (CertificateException e) {
            logger.error("Failed to create certificate factory", e);
        } catch (KeyStoreException e) {
            logger.error("Failed to get key store instance", e);
        } catch (KeyManagementException e) {
            logger.error("Failed to initialize SSL Context", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
