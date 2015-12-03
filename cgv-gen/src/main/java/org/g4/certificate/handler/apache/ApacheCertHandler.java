package org.g4.certificate.handler.apache;

import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.bean.CommandBean;
import org.g4.certificate.bean.DNameBean;
import org.g4.certificate.command.OpenSSLCommand;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateHandler;
import org.g4.certificate.parser.ApacheGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This handler class is to prepare the directories and assemble the commands which generate the certificates
 * User: Peter Zhang
 * Date: 11/19/14
 * Time: 11:34 AM
 */
public class ApacheCertHandler extends CertificateHandler {

    CertLogger logger = CertLogger.getLogger(ApacheCertHandler.class.getName());

    public boolean createPropertyFileTemplate(String target) {
        return FileUtil.createFile(
                FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_TEMPLATE_PATH + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE),
                target);
    }

    /**
     * Create necessary directories and files.
     * @return
     */
    public boolean prepareDirectories4Cert(ApacheGenParamParser parser) {
        boolean rtn = createCertRootPath();

        if (FileUtil.isDir(apacheRootPath)) {
            if (!FileUtil.deleteDir(apacheRootPath)) {
                logger.printToConsole("Fail to delete " + apacheRootPath + ", please check if you have opened any folders or files in it");
                return false;
            }
        }
        rtn = rtn && FileUtil.createDir(apacheRootPath);

        if(parser.isClientReq()){
            FileUtil.createDir(apacheClientPath);
        }
        FileUtil.createDir(apacheServerPath);
        FileUtil.createDir(apacheTempPath);

        return rtn;
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

        Map<String, DNameBean> dnMap = getDNameFromPropertyFile(paramMap);

        CertPropsBean caBean = getCACertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_CA), paramMap);
        CertPropsBean serverBean = getServerCertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_SERVER), paramMap);
        CertPropsBean clientBean = getClientCertProps(dnMap.get(CertParamTemplate.PARAMETER_PREFIX_CLIENT), paramMap);

        //if the password of CA private key is not specified, use the default value - caroot
        String caRootPass = paramMap.get(CertParamTemplate.PARAMETER_CA_ROOT_PASS);
        caRootPass = CertUtil.isNull(caRootPass) ? CertParamTemplate.CERT_CA_KEY_PASSWORD : caRootPass;
        certMap.put(CertParamTemplate.MAP_KEY_4_CAROOTPASS, caRootPass);
        certMap.put(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN, caBean);

        certMap.put(CertParamTemplate.MAP_KEY_4_SERVER_CERTBEAN, serverBean);
        certMap.put(CertParamTemplate.MAP_KEY_4_CLIENT_CERTBEAN, clientBean);

        return certMap;
    }

    /**
     * Retrieve the DName value from property file
     * @param paramMap
     * @return
     */
    private Map<String, DNameBean> getDNameFromPropertyFile(Map<String, String> paramMap) {
        Map<String, DNameBean> dnMap = new HashMap<String, DNameBean>();
        int dnameType = Integer.parseInt(paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE));
        DNameBean caDNBean = new DNameBean();
        DNameBean clientDNBean = new DNameBean();
        DNameBean serverDNBean = new DNameBean();

        if (dnameType == CertParamTemplate.PARAMETER_APACHE_DNAME_TYPE_GLOBAL) {
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_GLOBAL, paramMap);
            clientDNBean = caDNBean;
            serverDNBean = caDNBean;
        } else if (dnameType == CertParamTemplate.PARAMETER_APACHE_DNAME_TYPE_CLIENT_SERVER) {
            setDNameBean(caDNBean, CertParamTemplate.PARAMETER_PREFIX_CA, paramMap);
            setDNameBean(clientDNBean, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER, paramMap);
            serverDNBean = clientDNBean;
        } else {
            //exception number
        }

        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_CA, caDNBean);
        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_CLIENT, clientDNBean);
        dnMap.put(CertParamTemplate.PARAMETER_PREFIX_SERVER, serverDNBean);

        return dnMap;
    }

    private CertPropsBean getCACertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CA);
        cpBean.setCaFQDN(paramMap.get(CertParamTemplate.PARAMETER_CA_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    private CertPropsBean getServerCertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_SERVER);
        cpBean.setServerFQDN(paramMap.get(CertParamTemplate.PARAMETER_SERVER_FQDN));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    private CertPropsBean getClientCertProps(DNameBean dnBean, Map<String, String> paramMap) {
        CertPropsBean cpBean = new CertPropsBean();
        cpBean.setType(CertParamTemplate.CERT_GEN_TYPE_CLIENT);
        cpBean.setClientFQDN(paramMap.get(CertParamTemplate.PARAMETER_CLIENT_COMMON_NAME));
        convertDNameBeanToCertPropsBean(dnBean, cpBean);

        return cpBean;
    }

    public void delTempDir() {
        FileUtil.deleteDir(apacheTempPath);
    }

    public List<CommandBean> prepareApacheCommands(Map<String, Object> certMap, ApacheGenParamParser parser) {
        List<CommandBean> commandList = new ArrayList<CommandBean>();

        prepareCommands4Apache(commandList, certMap, parser);

        return commandList;
    }

    private void prepareCommands4Apache(List<CommandBean> commandList, Map<String, Object> certMap, ApacheGenParamParser parser) {
        prepareCACommands(commandList, certMap);
        prepareServerCommands(commandList, certMap);
        if(parser.isClientReq()){
            prepareClientCommands(commandList, certMap);
        }
    }

    public void MoveRequiredFilesFromTempToCertDir(ApacheGenParamParser parser){
        FileUtil.createFile(apacheTempPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE, apacheServerPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE);
        FileUtil.createFile(apacheTempPath + slash + CertParamTemplate.CERT_SERVER_KEY_APACHE, apacheServerPath + slash + CertParamTemplate.CERT_SERVER_KEY_APACHE);
        FileUtil.createFile(apacheTempPath + slash + CertParamTemplate.CERT_SERVER_CRT_APACHE, apacheServerPath + slash + CertParamTemplate.CERT_SERVER_CRT_APACHE);
        if(parser.isClientReq()){
            FileUtil.createFile(apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_P12_APACHE, apacheClientPath + slash + CertParamTemplate.CERT_CLIENT_P12_APACHE);
            FileUtil.createFile(apacheTempPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE, apacheClientPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE);
        }
    }

    /**
     * Combine command for CA generation
     * @param commandList
     * @param certMap
     */
    private void prepareCACommands(List<CommandBean> commandList, Map<String, Object> certMap){
        CertPropsBean bean = (CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_CA_CACERTBEAN);
        commandList.add(new CommandBean(
                OpenSSLCommand.generateCAKey(
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_KEY_APACHE,
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.generateCACert(
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE,
                        getDName4Apache(bean),
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );
    }

    /**
     * Combine commands for Server
     * @param commandList
     * @param certMap
     */
    private void prepareServerCommands(List<CommandBean> commandList, Map<String, Object> certMap){
        CertPropsBean bean = (CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_SERVER_CERTBEAN);
        commandList.add(new CommandBean(
                OpenSSLCommand.generateKey(
                        apacheTempPath + slash + CertParamTemplate.CERT_SERVER_KEY_APACHE))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.generateCsr4Apache(
                        apacheTempPath + slash + CertParamTemplate.CERT_SERVER_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_SERVER_CSR_APACHE,
                        getDName4Apache(bean)))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.signCertWithCACert(
                        apacheTempPath + slash + CertParamTemplate.CERT_SERVER_CSR_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_SERVER_CRT_APACHE,
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );
    }

    /**
     * Combine command for client
     * @param commandList
     * @param certMap
     */
    private void prepareClientCommands(List<CommandBean> commandList, Map<String, Object> certMap){
        CertPropsBean bean = (CertPropsBean) certMap.get(CertParamTemplate.MAP_KEY_4_CLIENT_CERTBEAN);
        commandList.add(new CommandBean(
                OpenSSLCommand.generateKey(
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_KEY_APACHE))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.generateCsr4Apache(
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_CSR_APACHE,
                        getDName4Apache(bean)))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.signCertWithCACert(
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_CSR_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_CERT_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CA_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_CRT_APACHE,
                        CertParamTemplate.CERT_CA_KEY_PASSWORD))
        );

        commandList.add(new CommandBean(
                OpenSSLCommand.convertCRTtoPFX(
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_CRT_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_KEY_APACHE,
                        apacheTempPath + slash + CertParamTemplate.CERT_CLIENT_P12_APACHE,
                        ""))
        );
    }

    public boolean prepareDirectories4Cert(List<CertPropsBean> list) {
        boolean rtn = true;
            rtn = rtn && FileUtil.createDir(apacheClientPath);
            rtn = rtn && FileUtil.createDir(apacheServerPath);
        return rtn;
    }
}
