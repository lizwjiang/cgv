package org.g4.certificate.command;

import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.Map;

/**
 * All commands used by OpenSSL to generate certificates
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class OpenSSLCommand {
    private static String slash = CertParamTemplate.CERT_SLASH;
    private static String opensslPath = FileUtil.getJarCurrentPath() + CertParamTemplate.CERT_ROOT_FOLDER;
    private static String openssl = opensslPath + slash + "openssl";
    private static String openssl_conf = opensslPath + slash + "openssl.conf";

    //%OPENSSL% genrsa -des3 -passout pass:%CAROOT_PASSWD% -out key/cakey.pem 2048(cakey.pem)
    public static String[] generateCAKey(String caKey, String caKeyPass) {
        String[] params = new String[]{
                openssl,
                "genrsa",
                "-des3",
                "-passout",
                "pass:" + caKeyPass,
                "-out",
                caKey,
                "2048"
        };
        return params;
    }

    //%OPENSSL% req -new -key key/cakey.pem -x509 -days 1095 -out certs\mycacert.pem -config ./openssl.conf -passin pass:%CAROOT_PASSWD% (mycacert.pem)
    //openssl req -new -key rsa_pri_nopw.pem -out crs.pem -subj /C=CN/ST=HB/L=SJZ/O=CCIT/OU=CCIT/CN=fym/emailAddress=fym0121@163.com
    public static String[] generateCACert(String caKey, String caCert, Map<String, String> dnameMap, String caKeyPass) {
        return generateCACert(caKey, caCert, CertUtil.convertMapToDName(dnameMap, 1), caKeyPass);
    }

    public static String[] generateCACert(String caKey, String caCert, String dName, String caKeyPass) {
        String[] params = new String[]{
                openssl,
                "req",
                "-new",
                "-key",
                caKey,
                "-x509",
                "-days",
                "1095",
                "-config",
                openssl_conf,
                "-subj",
                dName,
                "-passin",
                "pass:" + caKeyPass,
                "-out",
                caCert
        };
        return params;
    }

    //openssl pkcs8 -inform PEM -nocrypt -in exported.key -out exported_rsa.key
    public static String[] convertPEMToPKCS8(String inKey, String outKey){
        String[] params = new String[]{
                openssl,
                "pkcs8",
                "-inform",
                "PEM",
                "-nocrypt",
                "-in",
                inKey,
                "-out",
                outKey
        };
        return params;
    }

    //%OPENSSL% x509 -req -days 1095 -in crs/servercert_request.crs -CA certs/mycacert.pem -CAkey key/cakey.pem -CAcreateserial -out certs/smservercert.pem -passin pass:%CAROOT_PASSWD% (smservercert.pem)
    public static String[] signCertWithCACert(String requestCrt, String caCrt, String caKey, String cert, String caKeyPass) {
        String[] params = new String[]{
                openssl,
                "x509",
                "-req",
                "-days",
                "1095",
                "-in",
                requestCrt,
                "-CA",
                caCrt,
                "-CAkey",
                caKey,
                "-CAcreateserial",
                "-passin",
                "pass:" + caKeyPass,
                "-out",
                cert
        };
        return params;
    }

    /**Command for Apache openssl*/
    //%OPENSSL% genrsa -out key/server.key 2048(server.key)
    public static String[] generateKey(String key) {
        String[] params = new String[]{
                openssl,
                "genrsa",
                "-out",
                key,
                "2048"
        };
        return params;
    }

    //openssl req -config ./openssl.conf -new -key ssl/server.key -subj /C=CN/ST=HB/L=SJZ/O=CCIT/OU=CCIT/CN=idmvm01.asiapacific.hpqcorp.com/emailAddress=z@hp.com -out ssl/server.csr 
    public static String[] generateCsr4Apache(String key, String csr, String dName) {
        String[] params = new String[]{
                openssl,
                "req",
                "-config",
                openssl_conf,
                "-new",
                "-key",
                key,
                "-subj",
                dName,
                "-out",
                csr
        };
        return params;
    }

    //openssl pkcs12 -export -clcerts -in ssl/client.crt -inkey ssl/client.key -out ssl/client.p12
    public static String[] convertCRTtoPFX(String clientCrt, String clientKey, String outKey,String caKeyPass){
        String[] params = new String[]{
                openssl,
                "pkcs12",
                "-export",
                "-clcerts",
                "-in",
                clientCrt,
                "-inkey",
                clientKey,
                "-passout",
                "pass:" + caKeyPass,
                "-out",
                outKey
        };
        return params;
    }

}
