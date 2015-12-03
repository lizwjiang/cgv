package org.g4.certificate.command;

import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

/**
 * Unit test for OpenSSLCommand
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class OpenSSLCommandTest {
    private static String slash = CertParamTemplate.CERT_SLASH;
    private static String opensslPath = FileUtil.getJarCurrentPath() + CertParamTemplate.CERT_ROOT_FOLDER;
    private static String openssl = opensslPath + slash + "openssl";
    private static String openssl_conf = opensslPath + slash + "openssl.conf";

    @Test
    public void generateCAKey() {

        String[] params = new String[]{
                openssl,
                "genrsa",
                "-des3",
                "-passout",
                "pass:" + "caKeyPass",
                "-out",
                "caKey",
                "2048"
        };

        assertArrayEquals(params, OpenSSLCommand.generateCAKey("caKey", "caKeyPass"));
    }

    @Test
    public void generateCACert(){
        String[] params = new String[]{
                openssl,
                "req",
                "-new",
                "-key",
                "caKey",
                "-x509",
                "-days",
                "1095",
                "-out",
                "ca.pem",
                "-config",
                openssl_conf,
                "-subj",
                "dname",
                "-passin",
                "pass:" + "caKeyPass"
        };

        assertArrayEquals(params, OpenSSLCommand.generateCACert("caKey", "ca.pem", "dname", "caKeyPass"));
    }

    @Test
    public void signCertWithCACert(){
        String[] params = new String[]{
                openssl,
                "x509",
                "-req",
                "-days",
                "1095",
                "-in",
                "requestCrt",
                "-CA",
                "ca.pem",
                "-CAkey",
                "caKey",
                "-CAcreateserial",
                "-out",
                "my.pem",
                "-passin",
                "pass:" + "caKeyPass"
        };

        assertArrayEquals(params, OpenSSLCommand.signCertWithCACert("requestCrt", "ca.pem", "caKey", "my.pem", "caKeyPass"));
    }
}
