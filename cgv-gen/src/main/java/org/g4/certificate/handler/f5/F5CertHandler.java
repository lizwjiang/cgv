package org.g4.certificate.handler.f5;

import org.g4.certificate.aspect.CopyCacertsToJavaKeyStore;
import org.g4.certificate.aspect.ExportF5PrivKey;
import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.bean.CommandBean;
import org.g4.certificate.bean.DNameBean;
import org.g4.certificate.bean.KeytoolBean;
import org.g4.certificate.command.KeyToolCommand;
import org.g4.certificate.command.OpenSSLCommand;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateHandler;
import org.g4.certificate.parser.F5GenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The helper class to help generate all the certificates for SM web clients, SM RTE servers and F5 that is deployed
 * between client and RTE. e.g.:
 * 1. prepare environment including keytool, openSSL and the required folder
 * 2. prepare all the parameters according to f5 configuration file
 * 3. call executing class to generate certificates
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class F5CertHandler extends CertificateHandler {
    CertLogger logger = CertLogger.getLogger(F5CertHandler.class.getName());

    public boolean createPropertyFileTemplate(String target) {
        return FileUtil.createFile(
                FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_TEMPLATE_PATH + CertParamTemplate.SM_F5_CERT_PROPS_FILE),
                target);
    }

    /**
     * The data from property file in a map object needs to be parsed
     * and is put in another map that contains all the data for certificate generation
     *
     * @param paramMap contains all the data from property file, but is original data
     * @return
     */
    public Map<String, Object> getParameters4CertsFromPropertyFile(Map<String, String> paramMap) {
        Map<String, Object> certMap = new HashMap<String, Object>();
        List<CertPropsBean> list = new ArrayList<CertPropsBean>();

        Map<String, DNameBean> dnMap = getDNameFromPropertyFile(paramMap);

        CertPropsBean caBean = getCACertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_CA), paramMap);
        getClientCertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_CLIENT), paramMap, list);
        CertPropsBean f5Bean = getF5CertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_F5), paramMap);
        CertPropsBean serverBean = getServerCertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_SERVER), paramMap);

        //if the password of CA private key is not specified, use the default value - caroot
        String caRootPass = paramMap.get(CertParamTemplate.PARAMETER_CA_ROOT_PASS);
        caRootPass = CertUtil.isNull(caRootPass) ? CertParamTemplate.CERT_CA_KEY_PASSWORD : caRootPass;
        certMap.put(CertParamTemplate.MAP_KEY_4_CAROOTPASS, caRootPass);
        certMap.put(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS, CertParamTemplate.CERT_CA_CACERTS_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN, caBean);

        //for SM web clients
        certMap.put(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS, paramMap.get(CertParamTemplate.PARAMETER_CLIENT_KEYSTORE_PASS));
        certMap.put(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST, list);

        //for f5
        certMap.put(CertParamTemplate.MAP_KEY_4_F5_CERTBEAN, f5Bean);

        String f5ServerKeystorePass = paramMap.get(CertParamTemplate.PARAMETER_F5_SERVER_KEYSTOREPASS);
        if (CertUtil.isNull(f5ServerKeystorePass))
            f5ServerKeystorePass = CertParamTemplate.CERT_SERVER_KEYSTORE_PASSWORD;
        certMap.put(CertParamTemplate.MAP_KEY_4_F5SERVERKEYSTOREPASS, f5ServerKeystorePass);

        String f5ClientKeystorePass = paramMap.get(CertParamTemplate.PARAMETER_F5_CLIENT_KEYSTOREPASS);
        if (CertUtil.isNull(f5ClientKeystorePass))
            f5ClientKeystorePass = CertParamTemplate.CERT_CLIENT_KEYSTORE_PASSWORD;
        certMap.put(CertParamTemplate.MAP_KEY_4_F5CLIENTKEYSTOREPASS, f5ClientKeystorePass);

        //for SM RTE servers
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVER_CERTBEAN, serverBean);
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS, paramMap.get(CertParamTemplate.PARAMETER_SERVER_KEYSTORE_PASS));
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS, paramMap.get(CertParamTemplate.PARAMETER_SERVER_TRUSTEDCLIENTS_PWD));

        return certMap;
    }

    public List<CommandBean> prepareSMF5Commands(Map<String, Object> certMap, F5GenParamParser parser) {
        List<CommandBean> commandList = new ArrayList<CommandBean>();

        prepareCommands4SMWebtierAndF5(commandList, certMap, parser);

        if (!parser.isOffloading()) {
            prepareCommands4F5AndSMRTE(commandList, certMap, parser);
        }

        return commandList;
    }

    private void prepareCommands4SMWebtierAndF5(List<CommandBean> commandList, Map<String, Object> certMap, F5GenParamParser parser) {
        prepareCACommands(commandList, certMap, parser, false);
        prepareClientsAndF5Commands(commandList, certMap, parser);
    }

    private void prepareCommands4F5AndSMRTE(List<CommandBean> commandList, Map<String, Object> certMap, F5GenParamParser parser) {
        prepareCACommands(commandList, certMap, parser, true);
        prepareF5AndServerCommand(commandList, certMap, parser);
    }

    private void prepareF5AndServerCommand(List<CommandBean> commandList, Map<String, Object> certMap, F5GenParamParser parser) {
        KeytoolBean bean = new KeytoolBean();

        //For F5 that is used to connect RTE servers
        bean.setKeyStoreFile(f5TempLBServerPath + slash + CertParamTemplate.CERT_F5_KEYSTORE);
        bean.setKeyStorePass((String) certMap.get(CertParamTemplate.MAP_KEY_4_F5SERVERKEYSTOREPASS));
        bean.setKeyStoreAlias(CertParamTemplate.CERT_F5_KEY_ALIAS);
        bean.setReqCert(f5TempLBServerPath + slash + CertParamTemplate.CERT_CLIENT_REQUEST_CERTIFICATE);
        bean.setCertFile(f5LBServerPath + slash + CertParamTemplate.CERT_CLIENT_CERTIFICATE);
        bean.setCertPropsBean((CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_F5_CERTBEAN));
        bean.setTrustedClient(true);
        generateCommands(commandList, certMap, bean, "SF");

        //For SM RTE servers
        bean.setKeyStoreFile(f5ServerPath + slash + CertParamTemplate.CERT_SERVER_KEYSTORE);
        bean.setKeyStorePass((String) certMap.get(CertParamTemplate.MAP_KEY_4_F5SERVERKEYSTOREPASS));
        bean.setKeyStoreAlias(CertParamTemplate.CERT_SERVER_KEY_ALIAS);
        bean.setReqCert(f5TempServersPath + slash + CertParamTemplate.CERT_SERVER_REQUEST_CERTIFICATE);
        bean.setCertFile(f5TempServersPath + slash + CertParamTemplate.CERT_SERVER_CERTIFICATE);
        bean.setCertPropsBean((CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_SERVER_CERTBEAN));
        bean.setTrustedClient(false);
        generateCommands(commandList, certMap, bean, "S");
    }

    private void prepareClientsAndF5Commands(List<CommandBean> commandList, Map<String, Object> certMap, F5GenParamParser parser) {
        KeytoolBean bean = new KeytoolBean();

        //For F5 connected by SM web clients
        bean.setKeyStoreFile(f5TempLBClientPath + slash + CertParamTemplate.CERT_F5_KEYSTORE);
        bean.setKeyStorePass((String) certMap.get(CertParamTemplate.MAP_KEY_4_F5CLIENTKEYSTOREPASS));
        bean.setKeyStoreAlias(CertParamTemplate.CERT_F5_KEY_ALIAS);
        bean.setReqCert(f5TempLBClientPath + slash + CertParamTemplate.CERT_SERVER_REQUEST_CERTIFICATE);
        bean.setCertFile(f5LBClientPath + slash + CertParamTemplate.CERT_F5_CERTIFICATE);
        bean.setCertPropsBean((CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_F5_CERTBEAN));
        generateCommands(commandList, certMap, bean, "CF");

        //For SM web clients
        List<CertPropsBean> clientList = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        for (CertPropsBean cpBean : clientList) {
            String fqdn = cpBean.getClientFQDN();
            bean.setKeyStoreFile(f5ClientPath + slash + fqdn + slash + fqdn + CertParamTemplate.KEY_STORE_EXTENSION);
            bean.setKeyStorePass((String) certMap.get(CertParamTemplate.MAP_KEY_4_F5CLIENTKEYSTOREPASS));
            bean.setKeyStoreAlias(fqdn);
            bean.setReqCert(f5TempClientsPath + slash + fqdn + slash + CertParamTemplate.CERT_CLIENT_REQUEST_CERTIFICATE);
            bean.setCertFile(f5TempClientsPath + slash + fqdn + slash + CertParamTemplate.CERT_CLIENT_CERTIFICATE);
            bean.setCertPropsBean(cpBean);
            generateCommands(commandList, certMap, bean, "C");
        }
    }

    /**
     * This is a common method used to generate the commands used to SM web client, F5 and SM RTE.
     *
     * @param commandList
     * @param certMap
     * @param keytoolBean
     * @param type        C : SM web client, CF: F5 connected by clients, SF: F5 connecting to RTE servers, S: RTE server
     */
    private void generateCommands(List<CommandBean> commandList, Map<String, Object> certMap, KeytoolBean keytoolBean, String type) {
        String keyStoreFile = keytoolBean.getKeyStoreFile();
        String keyStoreAlias = keytoolBean.getKeyStoreAlias();
        String keyStorePass = keytoolBean.getKeyStorePass();
        String reqCert = keytoolBean.getReqCert();
        CertPropsBean bean = keytoolBean.getCertPropsBean();
        String certFile = keytoolBean.getCertFile();
        String f5TempCAPath = type.startsWith("S") ? f5TempServerCAPath : f5TempClientCAPath;
        //Here let key password be equals to store password of keystore. The reason is if they are different, when generating the request certificate,
        //the key password must be specified.
        String keyPass = keyStorePass;

        commandList.add(new CommandBean(
                KeyToolCommand.generatePrivateKeyForRSA(
                        keyStoreAlias,
                        keyStoreFile,
                        keyStorePass,
                        keyPass,
                        getDName(bean)))
        );
        commandList.add(new CommandBean(
                KeyToolCommand.generateCertToBeSigned(
                        keyStoreAlias,
                        keyStoreFile,
                        reqCert,
                        keyStorePass))
        );
        commandList.add(new CommandBean(
                OpenSSLCommand.signCertWithCACert(
                        reqCert,
                        f5TempCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        f5TempCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        certFile,
                        (String) certMap.get(CertParamTemplate.MAP_KEY_4_CAROOTPASS)))
        );
        //When configuring F5, the private key needs to be exported as base64 format, and then converted to pkcs8 format.
        if (type.equalsIgnoreCase("CF") || type.equalsIgnoreCase("SF")) {
            String f5TempClientOrServerPath = type.equalsIgnoreCase("CF") ? f5TempLBClientPath : f5TempLBServerPath;
            String exportKey = f5TempClientOrServerPath + slash + CertParamTemplate.CERT_F5_EXPORT_KEY;
            String exportKeyRSA = (type.equalsIgnoreCase("CF") ? f5LBClientPath : f5LBServerPath) + slash + CertParamTemplate.CERT_F5_EXPORT_KEY_RSA;

            commandList.add(new CommandBean(
                    KeyToolCommand.importCertToKSWithTrust(
                            keyStoreAlias,
                            keyStoreFile,
                            certFile,
                            keyStorePass),
                    new ExportF5PrivKey(),
                    new Object[]{keyStoreFile, keyStoreAlias, keyStorePass, exportKey},
                    "")
            );

            commandList.add(new CommandBean(
                    OpenSSLCommand.convertPEMToPKCS8(
                            exportKey,
                            exportKeyRSA))
            );
        } else {
            commandList.add(new CommandBean(
                    KeyToolCommand.importCertToKSWithTrust(
                            keyStoreAlias,
                            keyStoreFile,
                            certFile,
                            keyStorePass))
            );
        }
        // Below is only needed for SM RTE. For F5 configuration environment,
        // only need to generate a set of certificates that can be used for all RTE servers
        if (keytoolBean.isTrustedClient()) {
            commandList.add(new CommandBean(
                    KeyToolCommand.exportCertFromKS(
                            keyStoreAlias,
                            keyStoreFile,
                            f5TempServersPath + slash + CertParamTemplate.CERT_CLIENT_PUBLIC_KEY,
                            keyStorePass))
            );

            String trustedClientPassFromPropertyFile = (String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS);
            String trustedClientPass = !CertUtil.isNull(trustedClientPassFromPropertyFile) ?
                    trustedClientPassFromPropertyFile : CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE_PASSWORD;

            commandList.add(new CommandBean(
                    KeyToolCommand.importCertToKSWithoutTrust(
                            keyStoreAlias,
                            f5TempTrustedClientsKeystore,
                            f5TempServersPath + slash + CertParamTemplate.CERT_CLIENT_PUBLIC_KEY,
                            trustedClientPass))
            );
        }
    }

    private void prepareCACommands(List<CommandBean> commandList, Map<String, Object> certMap, F5GenParamParser parser, boolean isServer) {
        CertPropsBean bean = (CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN);
        String tempCAPath = isServer ? f5TempServerCAPath : f5TempClientCAPath;

        commandList.add(new CommandBean(
                OpenSSLCommand.generateCAKey(
                        tempCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        (String) certMap.get(CertParamTemplate.MAP_KEY_4_CAROOTPASS)))
        );
        commandList.add(new CommandBean(
                OpenSSLCommand.generateCACert(
                        tempCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        tempCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        getDName(bean),
                        (String) certMap.get(CertParamTemplate.MAP_KEY_4_CAROOTPASS)))
        );

        String javaKeystorePass = certMap.get(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS) != null ?
                (String) certMap.get(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS) : CertParamTemplate.CERT_CA_CACERTS_PASSWORD;
        String javaKeystore = parser.getJREHome() + CertParamTemplate.JRE_CACERTS_PATH +
                CertParamTemplate.CERT_SLASH + CertParamTemplate.CERT_JAVA_KEYSTORE;

        commandList.add(new CommandBean(
                KeyToolCommand.importCertToKSWithTrust(
                        isServer ? CertParamTemplate.CERT_CA_ROOT_CERT_IMPORT_ALIAS : CertParamTemplate.CERT_CA_ROOT_CERT_IMPORT_ALIAS_HWLB,
                        f5TempJavaKeystore,
                        tempCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        javaKeystorePass),
                new CopyCacertsToJavaKeyStore(),
                new Object[]{f5TempJavaKeystore, javaKeystore},
                "")
        );
    }

    public void MoveRequiredFilesFromTempToCertDir(Map<String, Object> certMap, F5GenParamParser parser) {
        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        for (CertPropsBean bean : list) {
            //For client, only need to copy cacerts into its own folder and the {client}.keystore is ready there.
            FileUtil.createFile(f5TempJavaKeystore, f5ClientPath + slash + bean.getClientFQDN() + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
        }

        //move the CA certificate to f5 client folder
        FileUtil.createFile(f5TempClientCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT, f5LBClientPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT);

        if (!parser.isOffloading()) {
            //copy cacerts and trustedclients.keystore to server. For f5, only need to copy once
            FileUtil.createFile(f5TempJavaKeystore, f5ServerPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
            FileUtil.createFile(f5TempTrustedClientsKeystore, f5ServerPath + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE);
        }
    }


    /**
     * Genereate web.xml for client and sm.ini for server when configure TSO or CAC or FIP or combination of them
     *
     * @certMap store the required info for certificate generation
     * including fqdn, password of key store of server, password of trusted clients
     */
    public void generateConfFile4SMF5(Map<String, Object> certMap, F5GenParamParser parser) {
        generateConfOfSMClient(certMap, f5TempClientsPath, f5ClientPath);
        if (!parser.isOffloading()) {
            generateConfOfSMServer(certMap, CertParamTemplate.CERT_SERVER_KEYSTORE, f5TempServersPath, f5ServerPath, CertParamTemplate.SM_INI_TYPE_F5);
        }

        generateSSLConfOfF5(certMap, parser);
    }

    private void generateSSLConfOfF5(Map<String, Object> certMap, F5GenParamParser parser) {
        generateF5SSLConf(certMap, true);

        if(!parser.isOffloading()){
            generateF5SSLConf(certMap, false);
        }
    }

    private void generateF5SSLConf(Map<String, Object> certMap, boolean isClientSSL) {
        StringBuffer sb = new StringBuffer();
        String cert = isClientSSL ? CertParamTemplate.CERT_F5_CERTIFICATE : CertParamTemplate.CERT_CLIENT_CERTIFICATE;
        sb.append(CertParamTemplate.SM_F5_CONF_CERTFICATE).append(" : ").append(cert).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_F5_CONF_KEY).append(" : ").append(CertParamTemplate.CERT_F5_EXPORT_KEY_RSA).append(CertParamTemplate.KEY_ENTER)
                .append(CertParamTemplate.SM_F5_CONF_PASS_PHASE).append(" : ").append(certMap.get(CertParamTemplate.MAP_KEY_4_CAROOTPASS)).append(CertParamTemplate.KEY_ENTER);

        if (isClientSSL)
            sb.append(CertParamTemplate.SM_F5_CONF_TRUSTED_CA).append(" : ").append(CertParamTemplate.CERT_CA_ROOT_CERT).append(CertParamTemplate.KEY_ENTER);

        String tempF5Path, f5Path, confFile;
        if (isClientSSL) {
            tempF5Path = f5TempLBClientPath;
            f5Path = f5LBClientPath;
            confFile = CertParamTemplate.SM_F5_SSL_CLIENT;
        } else{
            tempF5Path = f5TempLBServerPath;
            f5Path = f5LBServerPath;
            confFile = CertParamTemplate.SM_F5_SSL_SERVER;
        }
        FileUtil.createFile(new ByteArrayInputStream(sb.toString().getBytes()), tempF5Path + slash + confFile);
        FileUtil.createFile(tempF5Path + slash + confFile, f5Path + slash + confFile);
    }

    public void delTempDir() {
        FileUtil.deleteDir(f5TempPath);
    }

    public boolean prepareJavaKeyStoreEnv(F5GenParamParser parser) {
        return super.prepareJavaKeyStoreEnv(parser, f5TempJavaKeystore);
    }

    private CertPropsBean getCACertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CA);
        cpBean.setCaFQDN(paramMap.get(CertParamTemplate.PARAMETER_CA_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    private void getClientCertProps(DNameBean dnBean, Map<String, String> paramMap, List<CertPropsBean> list) {
        String clientList = paramMap.get(CertParamTemplate.PARAMETER_CLIENT_LIST);
        String[] clientArray = clientList.split(",");

        for (int i = 0; i < clientArray.length; i++) {
            CertPropsBean cpBean = new CertPropsBean();
            cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CLIENT);
            cpBean.setClientFQDN(paramMap.get(
                    CertParamTemplate.PARAMETER_PREFIX_CLIENT +
                            "" +
                            clientArray[i].trim() +
                            "." +
                            CertParamTemplate.PARAMETER_SUFFIX_FQDN));
            convertDNameBeanToCertPropsBean(dnBean, cpBean);
            list.add(cpBean);
        }
    }

    private CertPropsBean getF5CertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_LB);
        cpBean.setServerFQDN(paramMap.get(CertParamTemplate.PARAMETER_F5_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    private CertPropsBean getServerCertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_SERVER);
        cpBean.setServerFQDN(paramMap.get(CertParamTemplate.PARAMETER_SERVER_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    private Map<String, DNameBean> getDNameFromPropertyFile(Map<String, String> paramMap) {
        Map<String, DNameBean> dnMap = new HashMap<String, DNameBean>();
        int dnameType = Integer.parseInt(paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE));
        DNameBean caDNBean = new DNameBean();
        DNameBean clientDNBean = new DNameBean();
        DNameBean f5DNBean = new DNameBean();
        DNameBean serverDNBean = new DNameBean();

        if (dnameType == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_GLOBAL) {
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_GLOBAL, paramMap);
            clientDNBean = caDNBean;
            f5DNBean = caDNBean;
            serverDNBean = caDNBean;
        } else if (dnameType == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_CLIENT_F5_SERVER) {
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_CA, paramMap);
            setDNameBean(clientDNBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT_F5_SERVER, paramMap);
            f5DNBean = clientDNBean;
            serverDNBean = clientDNBean;
        } else if (dnameType == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_CLIENT_SERVER) {
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_CA, paramMap);
            setDNameBean(clientDNBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER, paramMap);
            serverDNBean = clientDNBean;
            setDNameBean(f5DNBean, CertParamTemplate.PARAMETER_PREFIX_F5, paramMap);
        } else {
            //CA, client, f5 and server use their own name
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_CA, paramMap);
            setDNameBean(clientDNBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT, paramMap);
            setDNameBean(f5DNBean, CertParamTemplate.PARAMETER_PREFIX_F5, paramMap);
            setDNameBean(serverDNBean, CertParamTemplate.PARAMETER_PREFIX_SERVER, paramMap);
        }

        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_CA, caDNBean);
        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_CLIENT, clientDNBean);
        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_F5, f5DNBean);
        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_SERVER, serverDNBean);

        return dnMap;
    }

    public boolean prepareDirectories4Cert(List<CertPropsBean> list, F5GenParamParser parser) {
        boolean rtn = createCertRootPath();

        if (FileUtil.isDir(f5RootPath)) {
            if (!FileUtil.deleteDir(f5RootPath)) {
                logger.printToConsole("Fail to delete " + f5RootPath + ", please check if you have opened any folders or files in it");
                return false;
            }
        }
        rtn = rtn && FileUtil.createDir(f5RootPath);

        FileUtil.createDir(f5ClientPath);
        FileUtil.createDir(f5LBPath);
        FileUtil.createDir(f5LBClientPath);
        FileUtil.createDir(f5TempPath);
        FileUtil.createDir(f5TempClientsPath);
        FileUtil.createDir(f5TempLBPath);
        FileUtil.createDir(f5TempLBClientPath);
        //FileUtil.createDir(f5TempClientsPath);
        FileUtil.createDir(f5TempCAPath);
        FileUtil.createDir(f5TempClientCAPath);

        if (!parser.isOffloading()) {
            FileUtil.createDir(f5ServerPath);
            FileUtil.createDir(f5LBServerPath);
            FileUtil.createDir(f5TempServersPath);
            FileUtil.createDir(f5TempLBServerPath);
            FileUtil.createDir(f5TempServerCAPath);
            FileUtil.createDir(f5TempTrustedClientsPath);
        }

        rtn = rtn && prepareDirectories4Cert(list);
        return rtn;
    }

    public boolean prepareDirectories4Cert(List<CertPropsBean> list) {
        boolean rtn = true;
        for (CertPropsBean bean : list) {
            rtn = rtn && FileUtil.createDir(f5ClientPath + slash + bean.getClientFQDN());
            rtn = rtn && FileUtil.createDir(f5TempClientsPath + slash + bean.getClientFQDN());
        }
        return rtn;
    }
}
