package org.g4.certificate.utilities;

import org.g4.certificate.facade.CertLogger;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The utility class which can facilitate certificate generation
 *
 * @author : Johnson Jiang
 * @since 1.0
 */
public class CertUtil {
    static CertLogger logger = CertLogger.getLogger(CertUtil.class.getName());

    /**
     * Check if the given string has a empty value
     *
     * @param str
     * @return
     */
    public static boolean isNull(String str) {
        return str == null || str.trim().equalsIgnoreCase("");
    }

    public static boolean isNum(String num) {
        String reg = "[\\d]+";
        return match(num, reg);
    }

    /**
     * Check if the string matches the pattern
     * Note this method should be private, any method using regular expression should write another one which should call this one
     *
     * @param str
     * @param reg
     * @return
     */
    private static boolean match(String str, String reg) {
        Pattern pattern = Pattern.compile(reg);
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();
    }

    /**
     * The dname format for keytool and openSSL is idfferent.
     * <p/>
     * OpenSSL : /C=CN/ST=HB/L=SJZ/O=CCIT/OU=CCIT/CN=fym/emailAddress=admin@email.com
     * Keytool : CN=(SS), OU=(SS), O=(SS), L=(BJ), ST=(BJ), C=(CN)
     *
     * @param dnMap
     * @param type  0:keytool, 1:OpenSSL. the default value is 0.
     * @return dname
     */
    public static String convertMapToDName(Map<String, String> dnMap, int type) {
        if (type == 0) {
            //Keytool
            return "\"" +
                    "CN=" + dnMap.get("CN") + "," +
                    "OU=" + dnMap.get("OU") + "," +
                    "O=" + dnMap.get("O") + "," +
                    "L=" + dnMap.get("L") + "," +
                    "ST=" + dnMap.get("ST") + "," +
                    "C=" + dnMap.get("C")
                    + "\"";
        } else if (type == 1) {
            //OpenSSL
            String dname = "\"/C=" + dnMap.get("C") +
                    "/ST=" + dnMap.get("ST") +
                    "/L=" + dnMap.get("L") +
                    "/O=" + dnMap.get("O") +
                    "/OU=" + dnMap.get("OU") +
                    "/CN=" + dnMap.get("CN");

            if (!isNull(dnMap.get("emailAddress")))
                dname += "/emailAddress=" + dnMap.get("emailAddress");
            dname += "\"";

            return dname;
        } else {
            return null;
        }

    }

    /**
     * Get the default dname. This is only for testing scenario
     *
     * @param type 0:Keytool 1:OpenSSL
     * @return
     */
    public static String getDefaultDName(int type, String cn) {
        if (type == 0) {
            return "\"CN=" + cn + ",OU=HPSW,O=HP,L=Shanghai,ST=Shanghai,C=CN\"";
        } else if (type == 1) {
            return "\"/CN=" + cn + "/OU=HPSW/O=HP/L=Shanghai/ST=Shanghai/C=CN/emailAddress=admin@hp.com\"";
        } else {
            CertExceptionHandler.handleException(new RuntimeException(""), "invalid type of default dname");
            return null;
        }

    }

    /**
     * Check if an array contains a value
     *
     * @param value
     * @param values
     * @return
     */
    public static boolean isInScope(String value, String[] values) {
        boolean isInScope = false;
        if (values == null || values.length == 0)
            return false;

        for (int i = 0; i < values.length; i++) {
            if (value.equalsIgnoreCase(values[i])) {
                isInScope = true;
                break;
            }
        }
        return isInScope;
    }

    /**
     * Read the string from the console
     *
     * @param prompt
     * @return
     */
    public static String readInput(String prompt) {
        System.out.print(prompt);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        try {
            return in.readLine();
        } catch (IOException e) {
            CertExceptionHandler.handleException(e, "unable to read input");
        }
        return null;
    }

    /**
     * print the command used to generated certificates to the log file
     *
     * @param commandList
     */
    public static void printCertCommand(List<String> commandList) {
        logger.debug(getCommandStr(commandList));
    }

    public static String getCommandStr(List<String> commandList) {
        String s = "";
        for (String _command : commandList) {
            s += _command + " ";
        }

        return s;
    }

    public static String getSpace(int num) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < num; i++) {
            sb.append(" ");
        }
        return sb.toString();
    }

    public static String getSpace(int num, String str) {
        if (isNull(str)) return "";
        return getSpace(num - str.length());
    }

    /**
     * Check if a port is being used in the specified host
     *
     * @param host
     * @param port
     * @return
     */
    public static boolean isPortUsing(String host, int port) {
        boolean flag = false;
        try {

            InetAddress theAddress = InetAddress.getByName(host);
            Socket socket = new Socket(theAddress, port);
            flag = true;
        } catch (IOException e) {
            //do nothing
        }
        return flag;
    }

    /**
     * Check if  aport is being used in the local host
     *
     * @param port
     * @return
     */
    public static boolean isLocalPortUsed(int port) {
        boolean flag = true;
        try {
            flag = isPortUsing("127.0.0.1", port);
        } catch (Exception e) {
        }
        return flag;
    }

    public static void closeInputStream(InputStream is) {
        try {
            if (is != null) {
                is.close();
            }
        } catch (IOException ioe) {
            //do nothing
        }
    }

    public static boolean isValidURL(String url) {
        String urlRegex = "\\b(https?|ftp|file|ldap)://"
                + "[-A-Za-z0-9+&@#/%?=~_|!:,.;]"
                + "*[-A-Za-z0-9+&@#/%=~_|]";
        return url.matches(urlRegex);
    }

    public static boolean isValidCert(String certFile) {
        CertificateFactory cf = null;
        FileInputStream fis = null;

        try {
            cf = CertificateFactory.getInstance("X.509");
            fis = new FileInputStream(certFile);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            if (CertUtil.isNull(cert.getSubjectDN().getName())) {
                return false;
            }
        } catch (Exception e) {
            return false;
        } finally {
            closeInputStream(fis);
        }
        return true;
    }

    public static X509CRL getLocalCRL(String crlFile) {
        FileInputStream fis = null;

        try {
            fis = new FileInputStream(new File(crlFile));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(fis);
            return crl;
        } catch (Exception e) {
            return null;
        } finally {
            closeInputStream(fis);
        }
    }

    public static int isValidCRL(String crlFile) {
        int rtn = 0;

        X509CRL crl = getLocalCRL(crlFile);
        if (crl != null) {
            if (CertUtil.isNull(crl.getIssuerX500Principal().getName()))
                rtn = 1;
            if (isCRLexpired(crl))
                rtn = 2;
        } else {
            rtn = 1;
        }
        return rtn;
    }

    public static boolean isCRLexpired(X509CRL crl) {
        Calendar today = Calendar.getInstance();

        try {
            if (today.getTime().after(crl.getNextUpdate())) {
                return true;
            }
        } catch (Exception e) {
            logger.error(ExceptionUtils.getRootCauseMessage(e), e);
            return true;
        }
        return false;
    }

    public static void showHelpMessage(String[] descArray, Map<String, String> paramMap) {
        StringBuffer sb = new StringBuffer();
        String enter = "\r\n";
        int spaceNum = 20;

        sb.append(descArray[0]).append(enter)
                .append("").append(enter)
                .append(descArray[1]).append(enter)
                .append("").append(enter);
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            sb.append(entry.getKey()).append(CertUtil.getSpace(spaceNum, entry.getKey())).append(entry.getValue()).append(enter);
        }
        sb.append("").append(enter)
                .append(descArray[2]);

        logger.printToConsole(sb.toString());
    }

    public static void showSecondLevelHelpMessage(String[] descArray, Map<String, String> paramMap) {
        showSecondLevelHelpMessage(descArray, paramMap, 20);
    }

    public static void showSecondLevelHelpMessage(String[] descArray, Map<String, String> paramMap, int spaceNum) {
        StringBuffer sb = new StringBuffer();
        String enter = "\r\n";

        sb.append(descArray[0]).append(enter)
                .append("").append(enter)
                .append(descArray[1]).append(enter)
                .append("").append(enter)
                .append(descArray[2]).append(enter)
                .append("").append(enter);
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            sb.append(" " + entry.getKey()).append(CertUtil.getSpace(spaceNum, entry.getKey())).append(entry.getValue()).append(enter);
        }
        sb.append("").append(enter)
                .append(descArray[3]);

        logger.printToConsole(sb.toString());
    }

    /**
     * Check if there are duplicated values in a string array
     *
     * @param strArray
     * @return
     */
    public static boolean isDuplicated(String[] strArray) {
        Set<String> strSet = new HashSet<String>();

        for (int i = 0; i < strArray.length; i++) {
            strSet.add(strArray[i]);
        }

        return (strSet.size() < strArray.length) ? true : false;
    }


    /**
     * Set Java key store with password in system property
     *
     * @param cacerts
     * @param password
     */
    public static void setCAKeyStore(String cacerts, String password) {
        System.setProperty("javax.net.ssl.trustStore", cacerts);
        System.setProperty("javax.net.ssl.trustStorePassword", password);
    }

    /**
     * enable SSL debug logs
     */
    public static void enableSSLDebugInfo() {
        System.setProperty("javax.net.debug", "ssl,handshake");
    }

    /**
     * Get a certificate from keystore by alias
     *
     * @param keyStore
     * @param storePass
     * @param alias
     * @return
     */
    public static Certificate loadCertFromKeyStore(String keyStore, String storePass, String alias) {
        X509Certificate cert = null;

        try {
            FileInputStream in = new FileInputStream(keyStore);
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(in, storePass.toCharArray());
            cert = (X509Certificate) ks.getCertificate(alias);
        } catch (Exception e) {
            String msg = "Exception is thrown when loading certificate from " + keyStore + " with " + alias + " alias";
            CertExceptionHandler.handleException(e, msg);
        }
        return cert;
    }


    /**
     * Check if the given keystore is valid or not.
     *
     * @param keystore
     * @param keystorePass
     * @return
     */
    public static boolean isValidKeystore(String keystore, String keystorePass) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(keystore);
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(fis, keystorePass.toCharArray());
            Enumeration e = ks.aliases();

            return e.hasMoreElements();
        } catch (Exception e) {
            logger.printToConsoleAndLogFile("Failed to validate " + keystore + ". The root cause is " + ExceptionUtils.getRootCauseMessage(e), e);
            return false;
        } finally {
            try {
                if (fis != null)
                    fis.close();
            } catch (IOException e) {
                //do nothing
            }
        }
    }
}
