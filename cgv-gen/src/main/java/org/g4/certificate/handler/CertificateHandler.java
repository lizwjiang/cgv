package org.g4.certificate.handler;

import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.bean.DNameBean;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CertGenParamParser;
import org.g4.certificate.utilities.*;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Some common methods and variables should be defined here for certificate generation.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public abstract class CertificateHandler {
    private CertLogger logger = CertLogger.getLogger(CertificateHandler.class.getName());
    public final String slash = CertParamTemplate.CERT_SLASH;

    protected final String certRootPath = FileUtil.getJarCurrentPath() + CertParamTemplate.CERT_ROOT_FOLDER;
    protected final String tsoRootPath = certRootPath + slash + CertParamTemplate.CERT_TRUSTEDSIGNON_FOLDER;
    protected final String apacheRootPath = certRootPath + slash + CertParamTemplate.CERT_APACHE_FOLDER;
    protected final String f5RootPath = certRootPath + slash + CertParamTemplate.CERT_F5_FOLDER;

    //For TSO
    protected final String tsoServerPath = tsoRootPath + slash + CertParamTemplate.CERT_SERVERS_FOLDER;
    protected final String tsoClientPath = tsoRootPath + slash + CertParamTemplate.CERT_CLIENTS_FOLDER;
    protected final String tsoLBPath = tsoRootPath + slash + CertParamTemplate.CERT_LB_FOLDER;
    protected final String tsoTempPath = tsoRootPath + slash + CertParamTemplate.CERT_TEMP_FOLDER;
    protected final String tsoTempServersPath = tsoTempPath + slash + CertParamTemplate.CERT_SERVERS_FOLDER;
    protected final String tsoTempClientsPath = tsoTempPath + slash + CertParamTemplate.CERT_CLIENTS_FOLDER;
    protected final String tsoTempLBPath = tsoTempPath + slash + CertParamTemplate.CERT_LB_FOLDER;
    protected final String tsoCAPath = tsoTempPath + slash + CertParamTemplate.CERT_CA_FOLDER;
    protected final String tsoTrustedClientsPath = tsoTempPath + slash + CertParamTemplate.CERT_TRUSTEDCLIENTS_FLODER;
    protected final String tsoTempJavaKeystorePath = tsoTempPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE;
    protected final String tsoTempTrustedClientsKeystorePath = tsoTrustedClientsPath + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE;

    //For F5
    protected final String f5ServerPath = f5RootPath + slash + CertParamTemplate.CERT_SERVERS_FOLDER;
    protected final String f5ClientPath = f5RootPath + slash + CertParamTemplate.CERT_CLIENTS_FOLDER;
    protected final String f5LBPath = f5RootPath + slash + CertParamTemplate.CERT_LB_FOLDER;
    protected final String f5LBClientPath = f5LBPath + slash + CertParamTemplate.CERT_LB_CLIENT_PROFILE;
    protected final String f5LBServerPath = f5LBPath + slash + CertParamTemplate.CERT_LB_SERVER_PROFILE;

    protected final String f5TempPath = f5RootPath + slash + CertParamTemplate.CERT_TEMP_FOLDER;
    protected final String f5TempServersPath = f5TempPath + slash + CertParamTemplate.CERT_SERVERS_FOLDER;
    protected final String f5TempClientsPath = f5TempPath + slash + CertParamTemplate.CERT_CLIENTS_FOLDER;
    protected final String f5TempLBPath = f5TempPath + slash + CertParamTemplate.CERT_LB_FOLDER;
    protected final String f5TempLBClientPath = f5TempLBPath + slash + CertParamTemplate.CERT_LB_CLIENT_PROFILE;
    protected final String f5TempLBServerPath = f5TempLBPath + slash + CertParamTemplate.CERT_LB_SERVER_PROFILE;
    protected final String f5TempCAPath = f5TempPath + slash + CertParamTemplate.CERT_CA_FOLDER;
    protected final String f5TempClientCAPath = f5TempCAPath + slash + CertParamTemplate.CERT_CLIENT_FOLDER;
    protected final String f5TempServerCAPath = f5TempCAPath + slash + CertParamTemplate.CERT_SERVER_FOLDER;
    protected final String f5TempTrustedClientsPath = f5TempPath + slash + CertParamTemplate.CERT_TRUSTEDCLIENTS_FLODER;
    protected final String f5TempTrustedClientsKeystore = f5TempTrustedClientsPath + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE;

    //For Apache
    protected final String apacheServerPath = apacheRootPath + slash + CertParamTemplate.CERT_SERVER_FOLDER;
    protected final String apacheClientPath = apacheRootPath + slash + CertParamTemplate.CERT_CLIENT_FOLDER;
    protected final String apacheTempPath = apacheRootPath + slash + CertParamTemplate.CERT_TEMP_FOLDER;

    // here we only use one cacerts which contains two CAs used to sign the certificates for client SSL and server SSL
    protected final String f5TempJavaKeystore = f5TempPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE;

    abstract public boolean prepareDirectories4Cert(List<CertPropsBean> list);

    /**
     * Create a root path where the certificate for TSO, Apache and F5 will be generated.
     * The root folder needs to be created at the first time. After that, it will not be deleted.
     */
    public boolean createCertRootPath() {
        boolean rtn = true;
        if (!FileUtil.isDir(certRootPath))
            rtn = FileUtil.createDir(certRootPath);
        return rtn;
    }

    /**
     * Parse the specified property file and put the valid data in a Map object.
     * This is only a simple conversion without any further analysis on any data.
     * Before pulling the data, need to check if what type of configuration file are used between
     * specified file and default file
     *
     * @param confFile
     * @return
     */
    public Map<String, String> getParametersMapFromPropertyFile(String confFile) {
        logger.debug("Extracting all the properties and values from " + confFile + " and put them into a map");
        Map<String, String> paramMap = PropertiesAnalyzer.convertProperties2Map(confFile);
        return paramMap;
    }

    /**
     * Copy Java certificate keystore called cacerts to the temp folder
     * Basically this is only used by SM itself.
     *
     * @param ph determine if the JRE path specified in command line is used.
     *           if not specify, use the environment variable called JAVA_HOME defined in system env
     */
    public boolean prepareJavaKeyStoreEnv(CertGenParamParser ph, String cacertsTempPath) {
        String JRECacertsPath = ph.getJREHome() + CertParamTemplate.JRE_CACERTS_PATH;
        String cacerts_orig = JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE_BACKUP;

        if (FileUtil.isFile(cacerts_orig)) {
            FileUtil.createFile(cacerts_orig, JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
        } else {
            FileUtil.createFile(JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE,
                    JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE_BACKUP);
        }
        //copy cacerts from JRE path to a temp folder where the env for certificate is being prepared.
        return FileUtil.createFile(JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE, cacertsTempPath);
    }

    /**
     * prepare OpenSSL environment. Need to copy required OpenSSL files under the openssl package into
     * {Jar root path}/CGA_GEN_CERTS/
     */
    public boolean prepareOpenSSLEnv() {
        return FileUtil.createFile(
                FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_OPENSSL_PATH + "openssl.exe"),
                certRootPath + slash + "openssl.exe") &&
                FileUtil.createFile(
                        FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_OPENSSL_PATH + "libeay32.dll"),
                        certRootPath + slash + "libeay32.dll") &&
                FileUtil.createFile(
                        FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_OPENSSL_PATH + "openssl.conf"),
                        certRootPath + slash + "openssl.conf") &&
                FileUtil.createFile(
                        FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_OPENSSL_PATH + "ssleay32.dll"),
                        certRootPath + slash + "ssleay32.dll");
    }

    /**
     * All the data configured in a property file is put into a Map object including dname related data.
     * Here needs to pull the dname data from Map and put them in DNameBean
     *
     * @param dnBean
     * @param keyword
     * @param paramMap
     */
    public void setDNameBean(DNameBean dnBean, String keyword, Map<String, String> paramMap) {
        dnBean.setOrganizationUnit(paramMap.get(keyword + ".ou"));
        dnBean.setOrganization(paramMap.get(keyword + ".o"));
        dnBean.setCity(paramMap.get(keyword + ".l"));
        dnBean.setProvince(paramMap.get(keyword + ".st"));
        dnBean.setCountryCode(paramMap.get(keyword + ".c"));
        dnBean.setEmail(paramMap.get(keyword + ".email"));
    }

    /**
     * @param dnBean
     * @param cpBean
     */
    public void convertDNameBeanToCertPropsBean(DNameBean dnBean, CertPropsBean cpBean) {
        cpBean.setOrganization(dnBean.getOrganization());
        cpBean.setOrganizationUnit(dnBean.getOrganizationUnit());
        cpBean.setCity(dnBean.getCity());
        cpBean.setProvince(dnBean.getProvince());
        cpBean.setCountryCode(dnBean.getCountryCode());
        cpBean.setEmail(dnBean.getEmail());
    }


    /**
     * get dname as the format in command from bean class
     *
     * @param bean
     * @return
     */
    public String getDName(CertPropsBean bean) {
        String fqdn = null;
        if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CA) {
            fqdn = bean.getCaFQDN();
        } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CLIENT) {
            fqdn = bean.getClientFQDN();
        } else {
            //Note, LB and server's FQDN use the same field called serverFQDN.
            fqdn = bean.getServerFQDN();
        }

        if (bean.isTest()) {
            if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CA) {
                return CertUtil.getDefaultDName(CertParamTemplate.CERT_COMMAND_TYPE_OPENSSL, fqdn);
            } else {
                return CertUtil.getDefaultDName(CertParamTemplate.CERT_COMMAND_TYPE_KEYTOOL, fqdn);
            }
        } else {
            Map<String, String> dnMap = new HashMap<String, String>();
            dnMap.put("CN", fqdn);
            dnMap.put("OU", bean.getOrganizationUnit());
            dnMap.put("O", bean.getOrganization());
            dnMap.put("L", bean.getCity());
            dnMap.put("ST", bean.getProvince());
            dnMap.put("C", bean.getCountryCode());

            if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CA) {
                return CertUtil.convertMapToDName(dnMap, CertParamTemplate.CERT_COMMAND_TYPE_OPENSSL);
            } else {
                return CertUtil.convertMapToDName(dnMap, CertParamTemplate.CERT_COMMAND_TYPE_KEYTOOL);
            }
        }
    }
    public String getDName4Apache(CertPropsBean bean){
        String fqdn = null;
        if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CA) {
            fqdn = bean.getCaFQDN();
        } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CLIENT) {
            fqdn = bean.getClientFQDN();
        } else {
            fqdn = bean.getServerFQDN();
        }
        Map<String, String> dnMap = new HashMap<String, String>();
        dnMap.put("CN", fqdn);
        dnMap.put("OU", bean.getOrganizationUnit());
        dnMap.put("O", bean.getOrganization());
        dnMap.put("L", bean.getCity());
        dnMap.put("ST", bean.getProvince());
        dnMap.put("C", bean.getCountryCode());
        return CertUtil.convertMapToDName(dnMap, CertParamTemplate.CERT_COMMAND_TYPE_OPENSSL);
    }
    /**
     * The dll and config files are in CGA_GEN_CERTS folder. After all the certificates are created,
     * need to remove them
     */
    public void delOpenSSL() {
        FileUtil.deleteFile(certRootPath + slash + "openssl.exe");
        FileUtil.deleteFile(certRootPath + slash + "libeay32.dll");
        FileUtil.deleteFile(certRootPath + slash + "openssl.conf");
        FileUtil.deleteFile(certRootPath + slash + "ssleay32.dll");
    }

    /**
     * During the generation of certificates of TSO, the cacerts file of JRE has been changed as the self CA cert will be imported in cacerts.
     * And the modified cacerts will replace the one in JRE path. After all the certificates are generated no matter whether the certificates are correct
     * should revert the cacerts in JRE path.
     */
    public void revertCacerts(CertGenParamParser ph) {
        String JRECacertsPath = ph.getJREHome() + CertParamTemplate.JRE_CACERTS_PATH;
        String cacerts_orig = JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE_BACKUP;

        if (FileUtil.isFile(cacerts_orig)) {
            FileUtil.createFile(cacerts_orig, JRECacertsPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
        }
    }

    /**
     * put the value from array to a bean
     *
     * @param certMsgs
     * @param bean
     */
    public void putValueFromArray2Bean(String[] certMsgs, CertPropsBean bean) {
        bean.setOrganizationUnit(certMsgs[0]);
        bean.setOrganization(certMsgs[1]);
        bean.setCity(certMsgs[2]);
        bean.setProvince(certMsgs[3]);
        bean.setCountryCode(certMsgs[4]);
    }

    /**
     * Get the FQDN from the input
     *
     * @param type
     * @return
     */
    public String specifyFQDN(String type) {
        return CertUtil.readInput(type + " FQDN (e.g., computer hostname): ");
    }

    /**
     * Get the all the properties of dname from user inputs on console
     *
     * @return
     */
    public String[] getCertMsg() {
        return new String[]{
                CertUtil.readInput("What is the name of your organization unit?"),
                CertUtil.readInput("What is the name of your organization?"),
                CertUtil.readInput("What is the name of your City and Locality?"),
                CertUtil.readInput("What is the name of your State or Province?"),
                CertUtil.readInput("What is the two-letter country code for this unit?")};
    }

    /**
     * Generate the tso configuration of client in web.xml
     *
     * @param certMap
     */
    public void generateConfOfSMClient(Map<String, Object> certMap, String tempClientsPath, String clientsPath) {
        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        for (CertPropsBean cpBean : list) {
            if (cpBean.getType() != CertParamTemplate.CERT_GEN_TYPE_CLIENT)
                continue;
            String clientFQDN = cpBean.getClientFQDN();
            Document doc = XMLUtil.getNewDocument();

            Element ele = XMLUtil.createRootElement(doc, CertParamTemplate.WEB_XML_WEBAPP);
            ele.setAttribute(CertParamTemplate.WEB_XML_VERSION, "2.5");

            Element keystore_initParam = XMLUtil.createElement(ele, CertParamTemplate.WEB_XML_INITPARAM);
            XMLUtil.createElement(keystore_initParam, CertParamTemplate.WEB_XML_PARAMNAE, "keystore");
            XMLUtil.createElement(keystore_initParam, CertParamTemplate.WEB_XML_PARAMVALUE, "/WEB-INF/" + clientFQDN + CertParamTemplate.KEY_STORE_EXTENSION);
            Element keystore_pass_initParam = XMLUtil.createElement(ele, CertParamTemplate.WEB_XML_INITPARAM);

            StringBuffer sb = new StringBuffer();
            sb.append("Beginning with SM9.34P2 and newer, the keystorePassword parameter has been moved to\r\n")
                .append("another file named webtier.properties that is located in the same folder with web.xml\r\n")
                    .append("If you are using one of those SM versions, you must not configure keystorePassword as given below,\r\n")
                    .append("instead you have to specify ")
                    .append("keystorePassword=")
                    .append((String) certMap.get(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS))
                    .append(" in webtier.properties");

            Comment keystorePassComment = doc.createComment(sb.toString());
            keystore_pass_initParam.getParentNode().insertBefore(keystorePassComment, keystore_pass_initParam);

            XMLUtil.createElement(keystore_pass_initParam, CertParamTemplate.WEB_XML_PARAMNAE, "keystorePassword");
            XMLUtil.createElement(keystore_pass_initParam, CertParamTemplate.WEB_XML_PARAMVALUE, (String) certMap.get(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS));

            XMLUtil.buildXmlFile(doc, tempClientsPath + slash + clientFQDN + slash + CertParamTemplate.SM_TSO_WEB_DOT_XML);
            FileUtil.createFile(tempClientsPath + slash + clientFQDN + slash + CertParamTemplate.SM_TSO_WEB_DOT_XML,
                    clientsPath + slash + clientFQDN + slash + CertParamTemplate.SM_TSO_WEB_DOT_XML);
        }
    }

    /**
     * @param certMap
     * @param keystore
     * @param tempServerPath
     * @param serverPath
     * @param type f5/tso
     */
    public void generateConfOfSMServer(Map<String, Object> certMap, String keystore, String tempServerPath, String serverPath, String type) {
        StringBuffer sb = new StringBuffer();
        sb.append("#Note: ");
        sb.append("If you copy all the below configuration to your sm.ini directly,  the existing sslConnector:0 should be commented out.").append(CertParamTemplate.KEY_ENTER);
        sb.append("#And httpsPort must be specified in sm.ini for each servlet").append(CertParamTemplate.KEY_ENTER).append(CertParamTemplate.KEY_ENTER);
        sb.append(CertParamTemplate.SM_INI_SSLCONNECTOR).append(":").append("1").append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_SSL).append(":").append("1").append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_SSL_REQCLIENTAUTH).append(":").append("2").append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_KEYSTOREFILE).append(":").append(keystore).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_KEYSTOREPASS).append(":").append(certMap.get(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS)).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_SSL_TRUSTEDCLIENTSJKS).append(":").append(CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_SSL_TRUSTEDCLIENTSPWD).append(":").append(certMap.get(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS)).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_TRUSTOREFILE).append(":").append(CertParamTemplate.CERT_JAVA_KEYSTORE).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_INI_TRUSTOREPASS).append(":").append(certMap.get(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS)).append(CertParamTemplate.KEY_ENTER);
        if (type.equalsIgnoreCase(CertParamTemplate.SM_INI_TYPE_F5)) {
            sb.append("external_lb");
        } else if (type.equalsIgnoreCase(CertParamTemplate.SM_INI_TYPE_TSO)) {
            sb.append(CertParamTemplate.SM_INI_TRUSTEDSIGNON).append(":").append("1");
        }

        FileUtil.createFile(new ByteArrayInputStream(sb.toString().getBytes()), tempServerPath + slash + CertParamTemplate.SM_TSO_INI);
        FileUtil.createFile(tempServerPath + slash + CertParamTemplate.SM_TSO_INI, serverPath + slash + CertParamTemplate.SM_TSO_INI);
    }

}
