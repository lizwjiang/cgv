package org.g4.certificate.handler.sso;

import org.g4.certificate.aspect.CopyCacertsToJavaKeyStore;
import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.bean.CommandBean;
import org.g4.certificate.bean.DNameBean;
import org.g4.certificate.checker.TSOPropsRuleChecker;
import org.g4.certificate.command.KeyToolCommand;
import org.g4.certificate.command.OpenSSLCommand;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateHandler;
import org.g4.certificate.parser.TSOGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The helper class to handle all the business logic of TSO certificate generation
 *
 * @author Johnson Jiang
 * @version 1.0
 * @see org.g4.certificate.handler.CertificateHandler
 * @since 1.0
 */
public class SMTSOCertHandler extends CertificateHandler {
    CertLogger logger = CertLogger.getLogger(SMTSOCertHandler.class.getName());

    /**
     * if the parameter named -template is specified in command line, need to generate a template file
     * which can be used to specify all the properties for TSO certificate generation
     *
     * @return
     */
    public boolean createTSOPropertyFileTemplate(String target) {
        return FileUtil.createFile(
                FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_TEMPLATE_PATH + CertParamTemplate.SM_TSO_CERT_PROPS_FILE),
                target);
    }

    /**
     * Get all the data that is used to generate commands for testing.
     * Here testing means only generating the certificates for a client and a server.
     * Also all the data is hardcoded except the FQDNs of the server and client
     *
     * @param ph
     * @return
     */
    public Map<String, Object> getParameters4Certs4Testing(TSOGenParamParser ph) {
        List<CertPropsBean> list = getParameters4CertsFromUserInput(ph.isTest());
        Map<String, Object> certMap = new HashMap<String, Object>();
        CertPropsBean cpBean = new CertPropsBean();

        cpBean.setCaFQDN("TestCA");
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CA);
        cpBean.setTest(ph.isTest());

        certMap.put(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN, cpBean);
        certMap.put(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS, CertParamTemplate.CERT_CA_CACERTS_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS, CertParamTemplate.CERT_SERVER_KEYSTORE_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS, CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS, CertParamTemplate.CERT_CLIENT_KEYSTORE_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST, list);

        return certMap;
    }

    /**
     * The root path is CGA_GEN_CERTS. There should always be Servers, Clients in Temp folders. Depending on the configuration specified, LB folder
     * will be created when the certificates will be used in HS system. Taking HS as an example, there are two clients, two servers and a LB. the details is follows
     * Servers : idmvm59.asiapacific.cpqcorp.net and idmvm51.asiapacific.cpqcorp.net
     * Clients : smcfrd110.asiapacific.cpqcorp.net and smcfrd119.asiapacific.cpqcorp.net
     * LB : idmvm08.asiapacific.cpqcorp.net
     * <p/>
     * So the directory structure would be
     * CGA_GEN_CERTS
     * | |_TrustedSignOn
     * |      |_ Servers
     * |      |     |_ idmvm59.asiapacific.cpqcorp.net
     * |      |     |_ idmvm51.asiapacific.cpqcorp.net
     * |      |_ Clients
     * |      |     |_ smcfrd110.asiapacific.cpqcorp.net
     * |      |     |_ smcfrd119.asiapacific.cpqcorp.net
     * |      |_ LB
     * |      |_ Temp
     * |           |_CA
     * |           |_Servers
     * |           |     |_idmvm59.asiapacific.cpqcorp.net
     * |           |     |_idmvm51.asiapacific.cpqcorp.net
     * |           |_LB
     * |           |_Clients
     * |           |     |_smcfrd110.asiapacific.cpqcorp.net
     * |           |     |_smcfrd119.asiapacific.cpqcorp.net
     * |           |_TrustedClients
     * |_Apache
     * |_F5
     * <p/>
     * Note: Cacerts and OpenSSL related files are in root folder.
     *
     * @param list
     */
    public boolean prepareDirectories4Cert(List<CertPropsBean> list) {
        boolean rtn = createCertRootPath();

        if (FileUtil.isDir(tsoRootPath)) {
            if (!FileUtil.deleteDir(tsoRootPath)) {
                logger.printToConsole("Fail to delete " + tsoRootPath + ", please check if you have open any folders or files in it");
                return false;
            }
        }
        rtn = rtn && FileUtil.createDir(tsoRootPath);
        FileUtil.createDir(tsoServerPath);
        FileUtil.createDir(tsoClientPath);
        FileUtil.createDir(tsoTempPath);
        FileUtil.createDir(tsoTempServersPath);
        FileUtil.createDir(tsoTempClientsPath);
        FileUtil.createDir(tsoCAPath);
        FileUtil.createDir(tsoTrustedClientsPath);

        for (CertPropsBean bean : list) {
            if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_LB) {
                FileUtil.createDir(tsoLBPath);
                rtn = rtn && FileUtil.createDir(tsoTempLBPath);
            } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_SERVER) {
                FileUtil.createDir(tsoServerPath + slash + bean.getServerFQDN());
                rtn = rtn && FileUtil.createDir(tsoTempServersPath + slash + bean.getServerFQDN());
            } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CLIENT) {
                FileUtil.createDir(tsoClientPath + slash + bean.getClientFQDN());
                FileUtil.createDir(tsoTempClientsPath + slash + bean.getClientFQDN());
            }
        }
        return rtn;
    }

    /**
     * Before sending the data that is from property file to generate certificate,
     * need to check if they are valid
     *
     * @param paramMap
     * @return
     */
    public boolean validateParametersFromPropertiesFile(Map<String, String> paramMap) {
        return TSOPropsRuleChecker.validate(paramMap);
    }

    /**
     * @param paramMap
     * @return
     */
    public Map<String, Object> getParameters4CertsFromPropertyFile(Map<String, String> paramMap) {
        Map<String, Object> certMap = new HashMap<String, Object>();
        List<CertPropsBean> list = new ArrayList<CertPropsBean>();

        CertPropsBean cpBean = getCAParamFromPropertyFile(paramMap);

        DNameBean serverDNBean = getServerDNameFromPropertyFile(paramMap);
        DNameBean clientDNBean = getClientDNameFromPropertyFile(paramMap);

        getServerOrLBParamFromPropertyFile(paramMap, list, serverDNBean);
        getClientParamFromPropertyFile(paramMap, list, clientDNBean);

        certMap.put(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN, cpBean);
        certMap.put(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS, CertParamTemplate.CERT_CA_CACERTS_PASSWORD);
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS, paramMap.get(CertParamTemplate.PARAMETER_SERVER_KEYSTORE_PASS));
        certMap.put(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS, paramMap.get(CertParamTemplate.PARAMETER_SERVER_TRUSTEDCLIENTS_PWD));
        certMap.put(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS, paramMap.get(CertParamTemplate.PARAMETER_CLIENT_KEYSTORE_PASS));
        certMap.put(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST, list);

        return certMap;
    }

    /**
     * Copy Java certificate keystore called cacerts to {Jar path}/TSO_Certificates/TEMP/
     * Basically this is only used by SM itself.
     *
     * @param ph determine if the JRE path specified in command line is used.
     *           if not specify, use the the configuration of env variable called JAVA_HOME
     */
    public boolean prepareJavaKeyStoreEnv(TSOGenParamParser ph) {
        return super.prepareJavaKeyStoreEnv(ph, tsoTempJavaKeystorePath);
    }

    public List<CommandBean> prepareTSOCommands(Map<String, Object> certMap, TSOGenParamParser ph) {
        List<CommandBean> commandList = new ArrayList<CommandBean>();

        prepareCACommands4TSO(commandList, certMap, ph);

        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        for (CertPropsBean bean : list) {
            prepareServerOrClientCommands4TSO(commandList, certMap, bean, ph);
        }

        return commandList;
    }

    public void MoveRequiredFilesFromTempToCertDir(List<CertPropsBean> list) {
        for (CertPropsBean bean : list) {
            if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_LB) {
                FileUtil.createFile(tsoTempJavaKeystorePath, tsoLBPath + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
                FileUtil.createFile(tsoTempTrustedClientsKeystorePath, tsoLBPath + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE);
            } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_SERVER) {
                FileUtil.createFile(tsoTempJavaKeystorePath, tsoServerPath + slash + bean.getServerFQDN() + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
                FileUtil.createFile(tsoTempTrustedClientsKeystorePath, tsoServerPath + slash + bean.getServerFQDN() + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE);
            } else {
                //For client, only need to copy cacerts into its own folder and the {client}.keystore is ready there.
                FileUtil.createFile(tsoTempJavaKeystorePath, tsoClientPath + slash + bean.getClientFQDN() + slash + CertParamTemplate.CERT_JAVA_KEYSTORE);
            }
        }
    }

    /**
     * Genereate web.xml for client and sm.ini for server when configure TSO or CAC or FIP or combination of them
     *
     * @certMap sore the required info for certificate generation including fqdn, password of key store of server, password of trusted clients
     */
    public void GenerateConfFile4TSO(Map<String, Object> certMap) {
        generateTSOConfOfServer(certMap);
        generateTSOConfOfClient(certMap);
    }

    public void delTempDir() {
        FileUtil.deleteDir(tsoTempPath);
    }


    private List<CertPropsBean> getParameters4CertsFromUserInput(boolean isTest) {
        List<CertPropsBean> list = new ArrayList<CertPropsBean>();
        logger.printToConsole("\nYou are about to be asked to enter the FQDNs of server and client that will be incorporated " +
                "into your certificate request.\n" +
                "Note: the FQDNs are mandatory and can not be left blank.\n\n" +
                "-----\n");
        CertPropsBean clientBean = getParamsFromUserInput(isTest, false);
        CertPropsBean serverBean = getParamsFromUserInput(isTest, true);

        if (!isTest) {
            String[] msgs = getCertMsg();
            putValueFromArray2Bean(msgs, clientBean);
            putValueFromArray2Bean(msgs, serverBean);

        }

        list.add(clientBean);
        list.add(serverBean);

        return list;
    }

    private CertPropsBean getParamsFromUserInput(boolean isTest, boolean isServer) {
        CertPropsBean cpBean = new CertPropsBean();
        String serverType = isServer ? "Server" : "Client";
        String fqdn = specifyFQDN(serverType);

        while (CertUtil.isNull(fqdn)) {
            fqdn = specifyFQDN(serverType + "FQDN is mandatory\n" + serverType);
        }

        cpBean.setTest(isTest);
        cpBean.setType(isServer ? CertParamTemplate.CERT_GEN_TYPE_SERVER : CertParamTemplate.CERT_GEN_TYPE_CLIENT);
        if (isServer) {
            cpBean.setServerFQDN(fqdn);
        } else {
            cpBean.setClientFQDN(fqdn);
        }

        return cpBean;
    }

    private void prepareCACommands4TSO(List<CommandBean> commandList, Map<String, Object> certMap, TSOGenParamParser ph) {
        CertPropsBean bean = (CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN);
        commandList.add(new CommandBean(
                OpenSSLCommand.generateCAKey(
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );
        commandList.add(new CommandBean(
                OpenSSLCommand.generateCACert(
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        getDName(bean),
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );


        String trustKeystorePass = certMap.get(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS) != null ?
                (String) certMap.get(CertParamTemplate.MAP_KEY_4_CATRUSTSTOREPASS) : CertParamTemplate.CERT_CA_CACERTS_PASSWORD;
        String cacerts = ph.getJREHome() + CertParamTemplate.JRE_CACERTS_PATH +
                CertParamTemplate.CERT_SLASH + CertParamTemplate.CERT_JAVA_KEYSTORE;

        commandList.add(new CommandBean(
                KeyToolCommand.importCertToKSWithTrust(
                        CertParamTemplate.CERT_CA_ROOT_CERT_IMPORT_ALIAS,
                        tsoTempJavaKeystorePath,
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        trustKeystorePass),
                new CopyCacertsToJavaKeyStore(),
                new Object[]{tsoTempJavaKeystorePath, cacerts},
                "")
        );
    }

    private void prepareServerOrClientCommands4TSO(List<CommandBean> commandList, Map<String, Object> certMap, CertPropsBean bean, TSOGenParamParser ph) {
        String fqdn = CertUtil.isNull(bean.getServerFQDN()) ? bean.getClientFQDN() : bean.getServerFQDN();

        String keyStoreAlias = (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_LB) ? CertParamTemplate.CERT_SERVER_KEY_ALIAS : fqdn;
        String keyStoreFile, keyStorePass, keyPass, reqCert, certFile;
        if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_LB) {
            keyStoreFile = tsoLBPath + slash + CertParamTemplate.CERT_SERVER_KEYSTORE;
            keyStorePass = !CertUtil.isNull((String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS)) ?
                    (String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS) : CertParamTemplate.CERT_SERVER_KEYSTORE_PASSWORD;
            reqCert = tsoTempLBPath + slash + CertParamTemplate.CERT_SERVER_REQUEST_CERTIFICATE;
            certFile = tsoTempLBPath + slash + CertParamTemplate.CERT_SERVER_CERTIFICATE;
        } else if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_SERVER) {
            keyStoreFile = tsoServerPath + slash + fqdn + slash + fqdn + CertParamTemplate.KEY_STORE_EXTENSION;
            keyStorePass = !CertUtil.isNull((String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS)) ?
                    (String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERKEYSTOREPASS) : CertParamTemplate.CERT_SERVER_KEYSTORE_PASSWORD;
            reqCert = tsoTempServersPath + slash + fqdn + slash + CertParamTemplate.CERT_SERVER_REQUEST_CERTIFICATE;
            certFile = tsoTempServersPath + slash + CertParamTemplate.CERT_SERVER_CERTIFICATE;
        } else {
            //should be client
            keyStoreFile = tsoClientPath + slash + fqdn + slash + fqdn + CertParamTemplate.KEY_STORE_EXTENSION;
            keyStorePass = !CertUtil.isNull((String) certMap.get(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS)) ?
                    (String) certMap.get(CertParamTemplate.MAP_KEY_4_CLIENTKEYSTOREPASS) : CertParamTemplate.CERT_CLIENT_KEYSTORE_PASSWORD;
            reqCert = tsoTempClientsPath + slash + fqdn + slash + CertParamTemplate.CERT_CLIENT_REQUEST_CERTIFICATE;
            certFile = tsoTempClientsPath + slash + CertParamTemplate.CERT_CLIENT_CERTIFICATE;
        }
        //Here let key password be equals to store password of keystore. The reason is if they are different, when generating the request certificate,
        //the key password must be specified.
        keyPass = keyStorePass;
        commandList.add(new CommandBean(
                KeyToolCommand.generatePrivateKey(
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
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_ROOT_CERT,
                        tsoCAPath + slash + CertParamTemplate.CERT_CA_KEY,
                        certFile,
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );
        commandList.add(new CommandBean(
                KeyToolCommand.importCertToKSWithTrust(
                        keyStoreAlias,
                        keyStoreFile,
                        certFile,
                        keyStorePass))
        );
        if (bean.getType() == CertParamTemplate.CERT_GEN_TYPE_CLIENT) {
            commandList.add(new CommandBean(
                    KeyToolCommand.exportCertFromKS(
                            keyStoreAlias,
                            keyStoreFile,
                            tsoTempClientsPath + slash + fqdn + slash + CertParamTemplate.CERT_CLIENT_PUBLIC_KEY,
                            keyStorePass))
            );

            String trustedClientPassFromPropertyFile = (String) certMap.get(CertParamTemplate.MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS);
            String trustedClientPass = !CertUtil.isNull(trustedClientPassFromPropertyFile) ?
                    trustedClientPassFromPropertyFile : CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE_PASSWORD;

            commandList.add(new CommandBean(
                    KeyToolCommand.importCertToKSWithoutTrust(
                            keyStoreAlias,
                            tsoTrustedClientsPath + slash + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE,
                            tsoTempClientsPath + slash + fqdn + slash + CertParamTemplate.CERT_CLIENT_PUBLIC_KEY,
                            trustedClientPass))
            );
        }
    }

    private DNameBean getServerDNameFromPropertyFile(Map<String, String> paramMap) {
        int dnameType = Integer.parseInt(paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE));
        DNameBean dnBean = new DNameBean();

        if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_GLOBAL, paramMap);
        } else if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER, paramMap);
        } else if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_SERVER, paramMap);
        }

        return dnBean;
    }

    private DNameBean getClientDNameFromPropertyFile(Map<String, String> paramMap) {
        int dnameType = Integer.parseInt(paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE));
        DNameBean dnBean = new DNameBean();

        if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_GLOBAL, paramMap);
        } else if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER, paramMap);
        } else if (dnameType == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT, paramMap);
        }

        return dnBean;
    }

    private CertPropsBean getCAParamFromPropertyFile(Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        DNameBean dnBean = getCADNameFromPropertyFile(paramMap);

        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CA);
        cpBean.setCaFQDN(paramMap.get(CertParamTemplate.PARAMETER_CA_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    /**
     * Get the CA's dname from property file. Actually all the data related to dname had been put in a Map.
     *
     * @param paramMap
     * @return bean class that is used to keep the dname data
     */
    private DNameBean getCADNameFromPropertyFile(Map<String, String> paramMap) {
        String dnameType = paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE);
        DNameBean dnBean = new DNameBean();
        if (CertUtil.isNull(dnameType) || Integer.parseInt(dnameType) == CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL) {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_GLOBAL, paramMap);
        } else {
            dnBean.setType(CertParamTemplate.PARAMETER_DNAME_TYPE_CA);
            setDNameBean(dnBean, CertParamTemplate.PARAMETER_PREFIX_CA, paramMap);
        }

        return dnBean;
    }


    private void getServerOrLBParamFromPropertyFile(Map<String, String> paramMap, List<CertPropsBean> list, DNameBean dnBean) {
        String serverList = paramMap.get(CertParamTemplate.PARAMETER_SERVER_LIST);

        String[] serverArray = serverList.split(",");

        for (int i = 0; i < serverArray.length; i++) {
            CertPropsBean cpBean = new CertPropsBean();
            if (serverArray[i].trim().equalsIgnoreCase("loadbalancer")) {
                cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_LB);
                cpBean.setServerFQDN(paramMap.get("server.loadbalancer.fqdn"));
            } else {
                cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_SERVER);
                cpBean.setServerFQDN(paramMap.get("server." + serverArray[i].trim() + ".fqdn"));
            }
            //Start handling dname
            convertDNameBeanToCertPropsBean(dnBean, cpBean);

            list.add(cpBean);
        }
    }

    private void getClientParamFromPropertyFile(Map<String, String> paramMap, List<CertPropsBean> list, DNameBean dnBean) {
        String clientList = paramMap.get(CertParamTemplate.PARAMETER_CLIENT_LIST);

        String[] clientArray = clientList.split(",");

        for (int i = 0; i < clientArray.length; i++) {
            CertPropsBean cpBean = new CertPropsBean();
            cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CLIENT);
            cpBean.setClientFQDN(paramMap.get("client." + clientArray[i].trim() + ".fqdn"));

            //Start handling dname
            convertDNameBeanToCertPropsBean(dnBean, cpBean);

            list.add(cpBean);
        }
    }

    /**
     * Generate the tso configuration of client in web.xml
     *
     * @param certMap
     */
    private void generateTSOConfOfClient(Map<String, Object> certMap) {
        generateConfOfSMClient(certMap, tsoTempClientsPath, tsoClientPath);
    }

    /**
     * Generate the tso configuration of RTE server in sm.ini
     *
     * @param certMap
     */
    private void generateTSOConfOfServer(Map<String, Object> certMap) {
        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        String keystore = null, tempServerPath = null, serverPath = null, fqdn = null;

        for (CertPropsBean cpBean : list) {
            if (cpBean.getType() != CertParamTemplate.CERT_GEN_TYPE_LB && cpBean.getType() != CertParamTemplate.CERT_GEN_TYPE_SERVER)
                continue;

            if (cpBean.getType() == CertParamTemplate.CERT_GEN_TYPE_LB) {
                keystore = CertParamTemplate.CERT_SERVER_KEYSTORE;
                tempServerPath = tsoTempLBPath;
                serverPath = tsoLBPath;
            } else if (cpBean.getType() == CertParamTemplate.CERT_GEN_TYPE_SERVER) {
                fqdn = cpBean.getServerFQDN();
                keystore = cpBean.getServerFQDN() + CertParamTemplate.KEY_STORE_EXTENSION;
                tempServerPath = tsoTempServersPath + slash + fqdn;
                serverPath = tsoServerPath + slash + fqdn;
            }

            generateConfOfSMServer(certMap, keystore, tempServerPath, serverPath, CertParamTemplate.SM_INI_TYPE_TSO);
        }
    }

}
