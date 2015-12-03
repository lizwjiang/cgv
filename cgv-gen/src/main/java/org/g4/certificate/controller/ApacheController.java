package org.g4.certificate.controller;

import org.g4.certificate.checker.ApachePropsRuleChecker;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateExecutor;
import org.g4.certificate.handler.apache.ApacheCertHandler;
import org.g4.certificate.parser.ApacheGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Controller class for Apache SSL certificates generation
 *
 * @author Peter Zhang
 * @version 1.0
 */
public class ApacheController {
    CertLogger logger = CertLogger.getLogger(SMF5Controller.class.getName());

    /**
     * Major method to handle Apache certificates generation request
     * @param parser
     * @return
     */
    public boolean handleApacheCertRequest(ApacheGenParamParser parser){
        ApacheCertHandler handler = new ApacheCertHandler();
        if(parser.isTemplate()){
            return handTemplateFileRequest(handler);
        }
        Map<String, String> paramMap = handler.getParametersMapFromPropertyFile(parser.getConfFile());

        if (!ApachePropsRuleChecker.validate(paramMap)) return false;

        Map<String, Object> certMap = handler.getParameters4CertsFromPropertyFile(paramMap);

        logger.printToConsole("\n" + CertParamTemplate.SYSTEM_PROMPT_START_HANDLING_MSG);

        if (!generateAllCertificates4Apache(certMap, parser, handler))
            return false;

        if (!parser.isKeepTemp())
            handler.delTempDir();

        handler.delOpenSSL();

        return true;
    }

    /**
     * To generate all the certificates file for Apache setup
     * @param certMap
     * @param parser
     * @param handler
     * @return
     */
    private boolean generateAllCertificates4Apache(Map<String, Object> certMap, ApacheGenParamParser parser, ApacheCertHandler handler) {
        if (!configureEnvForCertGeneration(parser, handler))
            return false;

        CertificateExecutor.execCommand(handler.prepareApacheCommands(certMap, parser), parser);

        //After all commands are executed, cacerts file will be generated in {Jar root path}/Apache/TEMP folder,
        //then need to copy ca.crt,server.key and server.crt to server folder and copy client.p12 to client folder.
        handler.MoveRequiredFilesFromTempToCertDir(parser);

        //handler.generateConfFile4SMF5(certMap, parser);

        return true;
    }

    /**
     * Prepare the directories and files before generation
     * @param parser
     * @param handler
     * @return
     */
    private boolean configureEnvForCertGeneration(ApacheGenParamParser parser, ApacheCertHandler handler) {
        return handler.prepareDirectories4Cert(parser) && handler.prepareOpenSSLEnv();
    }

    public boolean handTemplateFileRequest(ApacheCertHandler handler) {
        boolean rtn = handler.createPropertyFileTemplate(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE_TEMPLATE);
        if (rtn) {
            logger.printToConsole("The template named "
                    + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE_TEMPLATE
                    + " has been created successfully, please find it under "
                    + FileUtil.getJarCurrentPath());
        } else {
            logger.printToConsole("Failed to create the template file named "
                    + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE_TEMPLATE
                    + " under "
                    + FileUtil.getJarCurrentPath());
        }
        return rtn;
    }

    public void showApacheHelpMessage() {
        String[] descArray = new String[4];
        descArray[0] = "gen -apache [OPTION]...";
        descArray[1] = "Generate certificates for f5 that is used to replace SM load balancer:";
        descArray[2] = "Options:";
        descArray[3] = "Use \"gen -help\" for all available commands";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-kt", "Keep temp folder");
        paramMap.put("-config", "Specify the configuration file");
        paramMap.put("-jre_home", "Specify the path of JRE home");
        paramMap.put("-template", "Generate a template configuration file");

        CertUtil.showSecondLevelHelpMessage(descArray, paramMap);
    }
}
