package org.g4.certificate.command;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

/**
 * Unit test for KeyToolCommand
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class KeyToolCommandTest {

    @Test
    public void generatePrivateKey() throws Exception {
        String dname = "\"cn=idmvm15,ou=HPSW,o=HP,s=Shanghai,st=shanghai,c=CN\"";
        String[] params = new String[]{
                "keytool",
                "-genkey",
                "-validity",
                "1095",
                "-alias",
                "myKey",
                "-keystore",
                "my.keystore",
                "-dname",
                dname,
                "-storepass",
                "myStorePass",
                "-keypass",
                "myKeyPass",
                "-v"
        };
        assertArrayEquals(params, KeyToolCommand.generatePrivateKey("myKey", "my.keystore", "myStorePass", "myKeyPass", dname));
    }

    @Test
    public void generateCertToBeSigned() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-certreq",
                "-alias",
                "myCsr",
                "-keystore",
                "my.keystore",
                "-file",
                "my.csr",
                "-storepass",
                "myStorePass"
        };

        assertArrayEquals(params, KeyToolCommand.generateCertToBeSigned("myCsr", "my.keystore", "my.csr", "myStorePass"));
    }

    @Test
    public void testImportCertToKSWithTrust() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-import",
                "-noprompt",
                "-trustcacerts",
                "-alias",
                "my",
                "-keystore",
                "my.keystore",
                "-file",
                "my.pem",
                "-storepass",
                "myStorePass"
        };

        assertArrayEquals(params, KeyToolCommand.importCertToKSWithTrust("my", "my.keystore", "my.pem", "myStorePass"));

    }

    @Test
    public void importCertToKSWithoutTrust() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-import",
                "-noprompt",
                "-alias",
                "my",
                "-keystore",
                "my.keystore",
                "-file",
                "my.pem",
                "-storepass",
                "myStorePass"
        };

        assertArrayEquals(params, KeyToolCommand.importCertToKSWithoutTrust("my", "my.keystore", "my.pem", "myStorePass"));
    }

    @Test
    public void exportCertFromKS() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-export",
                "-alias",
                "my",
                "-keystore",
                "my.keystore",
                "-file",
                "my.pem",
                "-storepass",
                "myStorePass"
        };
        assertArrayEquals(params, KeyToolCommand.exportCertFromKS("my", "my.keystore", "my.pem", "myStorePass"));

    }

    @Test
    public void deleteCertFromKS() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-delete",
                "-alias",
                "my",
                "-keystore",
                "my.keystore",
                "-storepass",
                "myStorePass"
        };
        assertArrayEquals(params, KeyToolCommand.deleteCertFromKS("my", "my.keystore", "myStorePass"));

    }

    @Test
    public void viewKeyStore() throws Exception {
        String[] params = new String[]{
                "keytool",
                "-list",
                "-v",
                "-keystore",
                "my.keystore",
                "-storepass",
                "myStorePass"
        };
        assertArrayEquals(params, KeyToolCommand.viewKeyStore("my.keystore", "myStorePass"));
    }
}
