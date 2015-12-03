package org.g4.certificate.utilities;

import biz.source_code.base64Coder.Base64Coder;
import org.g4.certificate.facade.CertLogger;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;

/**
 * this is used to export private key from keystore and convert it to based64 format
 * @author Johnson Jiang
 * @version 1.0
 */
public class ExportPriv {
    static CertLogger logger = CertLogger.getLogger(ExportPriv.class.getName());

    public static boolean export(String keystore, String aliasName, String pass, String targetFile) {
        KeyStore ks = null;
        FileInputStream fis = null;
        char[] passPhrase = pass.toCharArray();

        try {
            ks = KeyStore.getInstance("JKS");

            File keystoreFile = new File(keystore);
            fis = new FileInputStream(keystoreFile);
            ks.load(fis, passPhrase);
        } catch (Exception e) {
            logger.error(ExceptionUtils.getRootCauseMessage(e), e);
            return false;
        }finally{
            CertUtil.closeInputStream(fis);
        }

        KeyPair kp = getPrivateKey(ks, aliasName, passPhrase);
        if (kp == null) {
            return false;
        }
        PrivateKey privKey = kp.getPrivate();
        char[] charArray = Base64Coder.encode(privKey.getEncoded());

        StringBuffer sb = new StringBuffer();
        sb.append("-----BEGIN PRIVATE KEY-----")
                .append("\r\n");
        for (int i = 0; i < charArray.length; i++) {
            char c = charArray[i];
            sb.append(c);
            if ((i + 1) % 64 == 0 && (i != charArray.length - 1)) {
                sb.append("\r\n");
            }
        }
        sb.append("\r\n")
                .append("-----END PRIVATE KEY-----");

        return FileUtil.createFile(new ByteArrayInputStream(sb.toString().getBytes()), targetFile);
    }

    private static KeyPair getPrivateKey(KeyStore keystore, String alias, char[] password) {
        try {
            // Get private key
            Key key = keystore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                Certificate cert = keystore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();
                return new KeyPair(publicKey, (PrivateKey) key);
            }
        } catch (UnrecoverableKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (KeyStoreException e) {
        }
        return null;
    }

}

