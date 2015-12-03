package org.g4.certificate.handler;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.ExceptionUtils;
import org.g4.certificate.utilities.FileUtil;
import org.g4.certificate.utilities.ParameterType;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * Helper that provides the utilities to handle SSL.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class SSLSocketHandler {
    private static CertLogger logger = CertLogger.getLogger(SSLSocketHandler.class.getName());

    /**
     * initial the SSL context with keystore and store password
     *
     * @param keystore
     * @param storePass
     * @return
     * @throws Exception
     */
    public static SSLContext initSSLContext(String keystore, String storePass) throws Exception {
        return initSSLContext(keystore, storePass, null, null);
    }

    /**
     * initial the SSL context with keystore, keystore password, trusted keystore and trusted keystore password.
     *
     * @param keystore
     * @param storePass
     * @param tKeystore
     * @param tStorePass
     * @return
     * @throws Exception
     */
    public static SSLContext initSSLContext(String keystore, String storePass, String tKeystore, String tStorePass) throws Exception {
        SSLContext ctx = null;

        ctx = SSLContext.getInstance(ParameterType.Protocol.SSL.toString());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(ParameterType.Algorithm.SunX509.name());

        KeyStore ks = KeyStore.getInstance(ParameterType.KeyStore.JKS.name());
        ks.load(new FileInputStream(keystore), storePass.toCharArray());
        kmf.init(ks, storePass.toCharArray());

        TrustManagerFactory tmf = null;
        if (!CertUtil.isNull(tKeystore)) {
            tmf = TrustManagerFactory.getInstance(ParameterType.Algorithm.SunX509.name());
            KeyStore tks = KeyStore.getInstance(ParameterType.KeyStore.JKS.name());
            tks.load(new FileInputStream(tKeystore), tStorePass.toCharArray());
            tmf.init(tks);
        }

        ctx.init(kmf.getKeyManagers(), tmf != null ? tmf.getTrustManagers() : null, null);

        return ctx;
    }


    public static boolean isCertificateExpired(String keystore, String keystorePass) {
        boolean isExpired = false;

        try {
            List<java.security.cert.Certificate> list = getCertListFromKeyStore(keystore, keystorePass);
            for (java.security.cert.Certificate cert : list) {
                if (!verifyCertificate(new Date(), cert)) {
                    isExpired = true;
                    break;
                }
            }

        } catch (Exception e) {
            logger.printToConsoleAndLogFile("Error happens when validating if the certificates in "
                    + FileUtil.getFileName(keystore)
                    + " are expired The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
        }
        return isExpired;
    }

    private static boolean verifyCertificate(Date date, java.security.cert.Certificate certificate) {
        boolean status = true;
        try {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            x509Certificate.checkValidity(date);
        } catch (Exception e) {
            status = false;
        }
        return status;
    }

    public static Date getExpirationDateOfCert(String keystore, String keystorePass){
        try {
            List<java.security.cert.Certificate> list = getCertListFromKeyStore(keystore, keystorePass);
            return ((X509Certificate)list.get(0)).getNotAfter();
        } catch (Exception e) {
            logger.printToConsoleAndLogFile("Error happens when validating if the certificates in "
                    + FileUtil.getFileName(keystore)
                    + " are expired The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
        }
        return null;
    }

    /**
     * Get certificate list from keystore
     *
     * @param keyStore
     * @param keyStorePass
     * @return
     */
    public static List<java.security.cert.Certificate> getCertListFromKeyStore(String keyStore, String keyStorePass) throws Exception {
        List<java.security.cert.Certificate> certList = new ArrayList<java.security.cert.Certificate>();
        FileInputStream in = new FileInputStream(keyStore);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(in, keyStorePass.toCharArray());

        Enumeration e = ks.aliases();

        while (e.hasMoreElements()) {
            certList.add(ks.getCertificate((String) e.nextElement()));
        }

        return certList;
    }

    public static void showCertificates(SSLSocket socket, String serverOrClient) {
        X509Certificate cert = null;
        SSLSession session = socket.getSession();
        try {
            cert = (X509Certificate) session.getPeerCertificates()[0];
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            System.err.println(socket.getSession().getPeerHost() + " did not present a valid certificate");
            return;
        }
        System.out.println(serverOrClient + " : "
                + session.getPeerHost()
                + " has presented a certificate belonging to"
                + "[" + cert.getSubjectDN() + "]\n"
                + "The certificate was issued by: \t"
                + "[" + cert.getIssuerDN() + "]");

    }


}
