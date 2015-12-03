package org.g4.certificate.command;

import org.g4.certificate.utilities.CertUtil;

import java.util.Map;

/**
 * All the commands to generate certificate by keytool
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class KeyToolCommand {

    //%KEYTOOL% -genkey -alias smserver -keystore key/server.keystore -storepass %SERVER_KEYSTORE_PASSWD% (server.keystore)
    public static String[] generatePrivateKey(String alias, String keyStore, String storePass, String keyPass, Map<String, String> dnMap) {
        return generatePrivateKey(alias, keyStore, storePass, keyPass, CertUtil.convertMapToDName(dnMap, 0));
    }

    public static String[] generatePrivateKey(String alias, String keyStore, String storePass, String keyPass, String dName) {
        String[] params = new String[]{
                "keytool",
                "-genkey",
                "-validity",
                "1095",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-dname",
                dName,
                "-storepass",
                storePass,
                "-keypass",
                keyPass,
                "-v"
        };
        return params;
    }
    //assume this method is only invoked when generating f5 related certificates. For TSO related ones, "-keyalg RSA" is not mandatory.
    public static String[] generatePrivateKeyForRSA(String alias, String keyStore, String storePass, String keyPass, String dName) {
        String[] params = new String[]{
                "keytool",
                "-genkey",
                "-keyalg",
                "RSA",
                "-validity",
                "1095",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-dname",
                dName,
                "-storepass",
                storePass,
                "-keypass",
                keyPass,
                "-v"
        };
        return params;
    }

    //%KEYTOOL% -certreq -alias smserver -keystore key/server.keystore -file crs/servercert_request.crs -storepass %SERVER_KEYSTORE_PASSWD% (servercert_request.crs)
    public static String[] generateCertToBeSigned(String alias, String keyStore, String requestCrt, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-certreq",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-file",
                requestCrt,
                "-storepass",
                storePass
        };
        return params;
    }

    //%KEYTOOL% -import -keystore certs/cacerts -trustcacerts -alias sm9.30.TSO8 -file certs/mycacert.pem -storepass %CACERT_PASSWD% (cacerts)
    public static String[] importCertToKSWithTrust(String alias, String keyStore, String cert, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-import",
                "-noprompt",
                "-trustcacerts",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-file",
                cert,
                "-storepass",
                storePass
        };
        return params;
    }

    public static String[] importCertToKSWithoutTrust(String alias, String keyStore, String cert, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-import",
                "-noprompt",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-file",
                cert,
                "-storepass",
                storePass
        };
        return params;
    }

    //%KEYTOOL% -export -alias %1 -keystore key/%1.keystore -file certs/clientpubkey.cert -storepass %CLIENT_KEYSTORE_PASSWD%
    public static String[] exportCertFromKS(String alias, String keyStore, String cert, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-export",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-file",
                cert,
                "-storepass",
                storePass
        };
        return params;
    }

    // keytool -delete -alias shuany -keystore yushan.keystore -storepass 123456
    public static String[] deleteCertFromKS(String alias, String keyStore, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-delete",
                "-alias",
                alias,
                "-keystore",
                keyStore,
                "-storepass",
                storePass
        };
        return params;
    }

    //keytool -list  -v -keystore e:\keytool\yushan.keystore -storepass 123456
    public static String[] viewKeyStore(String keyStore, String storePass) {
        String[] params = new String[]{
                "keytool",
                "-list",
                "-v",
                "-keystore",
                keyStore,
                "-storepass",
                storePass
        };
        return params;
    }

    //keytool -printcert -file yushan.crt
    public static String[] viewCertificate(String cert) {
        String[] params = new String[]{
                "keytool",
                "-printcert",
                "-file",
                cert
        };
        return params;
    }

}