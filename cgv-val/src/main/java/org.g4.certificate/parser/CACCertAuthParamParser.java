package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.List;

/**
 * Validate and parse all the parameters for CAC validation
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CACCertAuthParamParser extends CertAuthParamParser {
    private CertLogger logger = CertLogger.getLogger(CACCertAuthParamParser.class.getName());
    private final String directoryParam = "-d";
    private final String certParam = "-user_cert";
    private final String rootCertParam = "-ca_cert";
    private final String localCRLParam = "-local_crl";
    private final String onlineCRLParam = "-online_crl";
    private final String ocspServerParam = "-ocsp_server";
    private final String ocspResponderParam = "-ocsp_responder";
    private final String ldapCRLParam = "-ldap_crl";
    private final String smartCarTypeParam = "-smart_card_check";
    private final String disableCrlCheckParam = "-disable_crl_check";
    private final String proxyProtocolParam = "-proxy_protocol";
    private final String proxyHostParam = "-proxy_host";
    private final String proxyPortParam = "-proxy_port";
    private final String nonProxyHostsParam = "-nonproxy_hosts";
    private final String providerNameParam = "-provider_name";
    private final String providerClassParam = "-provider_class";

    private boolean directory;
    private boolean smartCard;
    private boolean localCRL;
    private boolean onlineCRLs;
    private boolean ocsp;
    private boolean ldapCRL;
    private boolean disableCrlCheck;
    private boolean proxy;

    private String certAuthRootDir = FileUtil.getJarCurrentPath() + CertParamTemplate.CERT_AUTH_ROOT_PATH + CertParamTemplate.CERT_SLASH;
    private String userCert;
    private String rootCerts;
    private String crls;
    private String onlineCRL;
    private String ocspServerPath;
    private String ocspResponderURL;
    private String ldapURL;
    private String proxyHost;
    private String proxyPort;
    private String nonProxyHosts;
    private String protocol;
    private String providerName;
    private String providerClass;
    private String[] crlArray;
    private String[] caArray;
    String[] paramArray = new String[]{
            directoryParam,
            certParam,
            rootCertParam,
            localCRLParam,
            onlineCRLParam,
            ocspServerParam,
            ocspResponderParam,
            //SM doesn't support downloading CRl from LDAP
            //ldapCRLParam,
            smartCarTypeParam,
            disableCrlCheckParam,
            proxyProtocolParam,
            proxyHostParam,
            proxyPortParam,
            nonProxyHostsParam,
            providerNameParam,
            providerClassParam
    };

    /**
     * The command should be like CertAuth -cac
     * -userCert        the certificate to be verified
     * -ca_cert         CA certificates, use comma separator if more than one
     * -local_crl       local CRL certificates, use comma separator if more than one
     * -online_crl      URL for CRL downloading
     * -ocsp            URL of OCSP for CRL
     * -ldap_crl        LDAP url for CRL
     * -smart_card      certificate type is smart card
     *
     * @param args
     */
    public boolean analyzeParams(String[] args) {
        int crlType = 0, ocspType = 0, proxyType = 0;
        if (!super.analyzeParams(args, paramArray))
            return false;

        for (int i = 0; i < args.length; i++) {
            if (args[i].equalsIgnoreCase(smartCarTypeParam)) {
                this.smartCard = true;
            } else if (args[i].equalsIgnoreCase(disableCrlCheckParam)) {
                this.disableCrlCheck = true;
            } else if (args[i].equalsIgnoreCase(directoryParam)) {
                this.directory = true;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setCertAuthRootDir((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(certParam)) {
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setUserCert((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(rootCertParam)) {
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setRootCerts((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(localCRLParam)) {
                this.localCRL = true;
                crlType++;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setCrls((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(onlineCRLParam)) {
                this.onlineCRLs = true;
                crlType++;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setOnlineCRLs((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(ocspServerParam)) {
                this.ocsp = true;
                ocspType = 1;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setOcspServerPath((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(ocspResponderParam)) {
                this.ocsp = true;
                ocspType = 1;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setOcspResponderURL((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(ldapCRLParam)) {
                this.ldapCRL = true;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setLdapURL((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(proxyProtocolParam)) {
                proxyType++;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setProtocol((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(proxyHostParam)) {
                proxyType++;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setProxyHost((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(proxyPortParam)) {
                proxyType++;
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setProxyPort((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            } else if (args[i].equalsIgnoreCase(nonProxyHostsParam)) {
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setNonProxyHosts((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            }else if (args[i].equalsIgnoreCase(providerNameParam)) {
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setProviderName((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            }else if (args[i].equalsIgnoreCase(providerClassParam)) {
                List list = validateParamWithValue(i, args, paramArray);
                if (list == null)
                    return false;
                setProviderClass((String) list.get(0));
                i = ((Integer) list.get(1)).intValue();
            }
        }

        //if -d is not specified, use the default directory. {current jar path}/CMT_VAL_CERTS/CommonAccessCard/
        if(!isDirectory()){
            setCertAuthRootDir(certAuthRootDir + CertParamTemplate.CERT_CAC_FOLDER + CertParamTemplate.CERT_SLASH);
        }

        if (!validateDirectory()) return false;
        if (!validateUserCert()) return false;
        if (!validateCACerts()) return false;
        if (!disableCrlCheck) {
            if (ocspType + crlType >= 2 || ocspType + crlType == 0) {
                logger.printToConsole("You have to specify one of local CRL, online CRL and OCSP");
                return false;
            }

            if (isLocalCRL() && !validateLocalCRLs()) return false;
            if (isOnlineCRLs() && !validateOnlineCRL()) return false;
            if (ocspType >= 1 && proxyType >= 1) {
                this.proxy = true;
                if (!validateProxy4OCSP()) return false;
            }
        }
        return true;
    }

    private boolean validateProxy4OCSP() {
        if (CertUtil.isNull(getProtocol())) {
            logger.printToConsole("You have to specify proxy protocol");
            return false;
        } else if (!CertUtil.isInScope(getProtocol(), CertParamTemplate.PROXY_PROTOCOL)) {
            logger.printToConsole("Invalid protocol, only http, https and ldap are supported");
            return false;
        }

        if (CertUtil.isNull(getProxyHost())) {
            logger.printToConsole("You have to specify proxy host");
            return false;
        }
        if (CertUtil.isNull(getProxyPort())) {
            logger.printToConsole("You have to specify proxy port");
            return false;
        }
        return true;
    }

    private boolean validateDirectory() {
        if (!FileUtil.isDir(getCertAuthRootDir())) {
            logger.printToConsole(getCertAuthRootDir() + " is an invalid path");
            return false;
        } else {
            String tempDir = getCertAuthRootDir().replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
            if (!tempDir.endsWith(CertParamTemplate.CERT_SLASH)) {
                setCertAuthRootDir(tempDir + CertParamTemplate.CERT_SLASH);
            }
        }
        return true;
    }

    private boolean validateUserCert() {
        if (CertUtil.isNull(getUserCert())) {
            logger.printToConsole("user certificate is missing in command line, please use " + certParam + " to specify");
            return false;
        } else {
            // the purpose to remove the double quotes (") is user needs to specify one path which contains space,
            // so need to use double quotes (") to wrap up.
            String certFile = getUserCert().replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();

            if (isDirectory())
                certFile = getCertAuthRootDir() + certFile;
            if (!FileUtil.isFile(certFile)) {
                logger.printToConsole(certFile + " is a invalid file");
                return false;
            } else {
                if (!CertUtil.isValidCert(certFile)) {
                    logger.printToConsole(certFile + " is a invalid certificate");
                    return false;
                }
            }
            setUserCert(certFile);
        }
        return true;
    }

    private boolean validateCACerts() {
        if (CertUtil.isNull(getRootCerts())) {
            logger.printToConsole("CA certificates are missing in command line, please use " + rootCertParam + " to specify");
            return false;
        } else {
            String tempRootCerts = getRootCerts().replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
            setRootCerts(tempRootCerts);

            String[] certArray = tempRootCerts.split(CertParamTemplate.CERT_COMMA);
            String[] caArray = new String[certArray.length];
            for (int i = 0; i < certArray.length; i++) {
                String rootCert = certArray[i];
                if (isDirectory()) {
                    rootCert = getCertAuthRootDir() + rootCert;
                }
                if (!FileUtil.isFile(rootCert)) {
                    logger.printToConsole(rootCert + " is a invalid file");
                    return false;
                } else {
                    if (!CertUtil.isValidCert(rootCert)) {
                        logger.printToConsole(rootCert + " is a invalid certificate");
                        return false;
                    }
                }
                caArray[i] = rootCert;
            }
            setCAArray(caArray);
        }
        return true;
    }

    private boolean validateLocalCRLs() {
        if (CertUtil.isNull(getCrls())) {
            logger.printToConsole("CRLs are missing in command line, please use " + localCRLParam + " to specify");
            return false;
        } else {
            String tempCRLs = getCrls().replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
            setCrls(tempCRLs);

            String[] crlArray = tempCRLs.split(CertParamTemplate.CERT_COMMA);
            String[] tempCRLArray = new String[crlArray.length];
            for (int i = 0; i < crlArray.length; i++) {
                String crl = crlArray[i];
                if (isDirectory()) {
                    crl = getCertAuthRootDir() + crl;
                }
                if (!FileUtil.isFile(crl)) {
                    logger.printToConsole(crl + " is a invalid file");
                    return false;
                } else {
                    int rtn = CertUtil.isValidCRL(crl);
                    if (rtn == 1) {
                        logger.printToConsole(crl + " is a invalid CRL");
                        return false;
                    } else if (rtn == 2) {
                        logger.printToConsole(crl + " is expired, you need to get a valid CRL");
                        return false;
                    }
                }
                tempCRLArray[i] = crl;
            }
            setCrlArray(tempCRLArray);
        }
        return true;
    }

    private boolean validateOnlineCRL() {
        if (isOnlineCRLs()) {
            if (!CertUtil.isValidURL(getOnlineCRL())) {
                logger.printToConsole(getOnlineCRL() + " is a invalid URL for online CRL");
                return false;
            }
        }
        return true;
    }

    public boolean isDirectory() {
        return directory;
    }

    public boolean isSmartCard() {
        return smartCard;
    }

    public boolean isLocalCRL() {
        return localCRL;
    }

    public boolean isOnlineCRLs() {
        return onlineCRLs;
    }

    public boolean isOcsp() {
        return ocsp;
    }

    public boolean isLdapCRL() {
        return ldapCRL;
    }

    public boolean disableCRLCheck() {
        return disableCrlCheck;
    }

    public String getCrls() {
        return crls;
    }

    public void setCrls(String crls) {
        this.crls = crls;
    }

    public String getRootCerts() {
        return rootCerts;
    }

    public void setRootCerts(String rootCerts) {
        this.rootCerts = rootCerts;
    }

    public String getUserCert() {
        return userCert;
    }

    public void setUserCert(String userCert) {
        this.userCert = userCert;
    }

    public String getOcspServerPath() {
        return ocspServerPath;
    }

    public void setOcspServerPath(String ocspServerPath) {
        this.ocspServerPath = ocspServerPath;
    }

    public String getOnlineCRL() {
        return onlineCRL;
    }

    public void setOnlineCRLs(String onlineCRL) {
        this.onlineCRL = onlineCRL;
    }

    public String getOcspResponderURL() {
        return ocspResponderURL;
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        this.ocspResponderURL = ocspResponderURL;
    }

    public String getLdapURL() {
        return ldapURL;
    }

    public void setLdapURL(String ldapURL) {
        this.ldapURL = ldapURL;
    }

    public String getCertAuthRootDir() {
        return certAuthRootDir;
    }

    public void setCertAuthRootDir(String certAuthRootDir) {
        this.certAuthRootDir = certAuthRootDir;
    }

    public String[] getCAArray() {
        return caArray;
    }

    public void setCAArray(String[] caArray) {
        this.caArray = caArray;
    }

    public String[] getCrlArray() {
        return crlArray;
    }

    public void setCrlArray(String[] crlArray) {
        this.crlArray = crlArray;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getNonProxyHosts() {
        return nonProxyHosts;
    }

    public void setNonProxyHosts(String nonProxyHosts) {
        this.nonProxyHosts = nonProxyHosts;
    }

    public String getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public boolean isProxy() {
        return proxy;
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public String getProviderClass() {
        return providerClass;
    }

    public void setProviderClass(String providerClass) {
        this.providerClass = providerClass;
    }
}
