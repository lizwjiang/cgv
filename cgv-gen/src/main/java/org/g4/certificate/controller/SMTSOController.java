package org.g4.certificate.controller;

import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateExecutor;
import org.g4.certificate.handler.sso.SMTSOCertHandler;
import org.g4.certificate.parser.TSOGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller class for SM TSO certificate generation
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class SMTSOController {
    CertLogger logger = CertLogger.getLogger(SMTSOController.class.getName());

    public boolean handleTSOCertGenRequest(TSOGenParamParser parser) {
        SMTSOCertHandler handler = new SMTSOCertHandler();
        Map<String, Object> certMap;

        if (parser.isTest()) {
            //If "-t" parameter is enabled, the certificates are only generated for a client and a server.
            //And also all the parameters will be hardcoded such as dname, CA trust store password etc.
            certMap = handler.getParameters4Certs4Testing(parser);
        } else {
            if (parser.isTemplate()) {
                return handTemplateFileRequest(handler);
            }

            certMap = getParameters4CertsFromPropertyFile(parser, handler);
        }
        //if parameters are from property file and the validation on them is not passed, return null;
        if (certMap == null)
            return false;

        logger.printToConsole("\n" + CertParamTemplate.SYSTEM_PROMPT_START_HANDLING_MSG);
        if (!generateAllCertificates4SMTSO(certMap, parser, handler))
            return false;

        if (!parser.isKeepTemp())
            handler.delTempDir();

        handler.delOpenSSL();
        handler.revertCacerts(parser);

        return true;
    }

    public boolean handTemplateFileRequest(SMTSOCertHandler handler) {
        boolean rtn = handler.createTSOPropertyFileTemplate(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE_TEMPLATE);
        if (rtn) {
            logger.printToConsole("The template named "
                    + CertParamTemplate.SM_TSO_CERT_PROPS_FILE_TEMPLATE
                    + " has been created successfully, please find it under "
                    + FileUtil.getJarCurrentPath());
        } else {
            logger.printToConsole("Failed to create the template file named "
                    + CertParamTemplate.SM_TSO_CERT_PROPS_FILE_TEMPLATE
                    + " under "
                    + FileUtil.getJarCurrentPath());
        }
        return rtn;
    }

    public boolean generateAllCertificates4SMTSO(Map<String, Object> certMap, TSOGenParamParser ph, SMTSOCertHandler handler) {
        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);

        if (!configureEnvForCertGeneration(list, ph, handler)) return false;

        CertificateExecutor.execCommand(handler.prepareTSOCommands(certMap, ph), ph);

        /*
           After all commands are executed, cacerts file will be generated in {Jar root path}/TrustedSignOn/Temp folder
           and trustedclients.keystore will be generated in {Jar root path}/Temp/trustedclients
           so need to copy trustedclients.keystore to each server folder and copy cacerts to all servers and clients folder.
        */
        handler.MoveRequiredFilesFromTempToCertDir(list);

        handler.GenerateConfFile4TSO(certMap);

        return true;
    }

    private Map<String, Object> getParameters4CertsFromPropertyFile(TSOGenParamParser ph, SMTSOCertHandler handler) {
        Map<String, String> paramMap = handler.getParametersMapFromPropertyFile(ph.getConfFile());

        if (!handler.validateParametersFromPropertiesFile(paramMap)) return null;

        Map<String, Object> certMap = handler.getParameters4CertsFromPropertyFile(paramMap);

        return certMap;
    }

    private boolean configureEnvForCertGeneration(List<CertPropsBean> list, TSOGenParamParser ph, SMTSOCertHandler handler) {
        return handler.prepareDirectories4Cert(list)
                && handler.prepareOpenSSLEnv()
                && handler.prepareJavaKeyStoreEnv(ph);
    }

    public void showTSOHelpMessage() {
        String[] descArray = new String[4];
        descArray[0] = "gen -tso [OPTION]...";
        descArray[1] = "Generate certificates for trusted sign on:";
        descArray[2] = "Options:";
        descArray[3] = "Use \"gen -help\" for all available commands";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-t", "Generate TSO certificates for only one SM web client and one SM server");
        paramMap.put("-kt", "Keep temp folder");
        paramMap.put("-config", "Specify the configuration file");
        paramMap.put("-jre_home", "Specify the path of JRE home");
        paramMap.put("-template", "Generate a template configuration file");

        CertUtil.showSecondLevelHelpMessage(descArray, paramMap);
    }
}
