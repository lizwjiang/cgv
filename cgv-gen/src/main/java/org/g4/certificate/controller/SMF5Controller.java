package org.g4.certificate.controller;

import org.g4.certificate.bean.CertPropsBean;
import org.g4.certificate.checker.F5PropsRuleChecker;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.CertificateExecutor;
import org.g4.certificate.handler.f5.F5CertHandler;
import org.g4.certificate.parser.F5GenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The controller class for F5 certificate generation
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class SMF5Controller {
    CertLogger logger = CertLogger.getLogger(SMF5Controller.class.getName());

    public boolean handF5CertGenRequest(F5GenParamParser parser) {
        F5CertHandler handler = new F5CertHandler();
        if (parser.isTemplate())
            return handTemplateFileRequest(handler);

        Map<String, String> paramMap = handler.getParametersMapFromPropertyFile(parser.getConfFile());

        if (!F5PropsRuleChecker.validate(paramMap, parser.isOffloading())) return false;

        Map<String, Object> certMap = handler.getParameters4CertsFromPropertyFile(paramMap);

        logger.printToConsole("\n" + CertParamTemplate.SYSTEM_PROMPT_START_HANDLING_MSG);
        if (!generateAllCertificates4SMF5(certMap, parser, handler))
            return false;

        if (!parser.isKeepTemp())
            handler.delTempDir();

        handler.delOpenSSL();
        handler.revertCacerts(parser);

        return true;
    }

    private boolean generateAllCertificates4SMF5(Map<String, Object> certMap, F5GenParamParser parser, F5CertHandler handler) {
        if (!configureEnvForCertGeneration(certMap, parser, handler))
            return false;

        CertificateExecutor.execCommand(handler.prepareSMF5Commands(certMap, parser), parser);

        /*
           After all commands are executed, cacerts file will be generated in {Jar root path}/TrustedSignOn/Temp folder
           and trustedclients.keystore will be generated in {Jar root path}/Temp/trustedclients
           so need to copy trustedclients.keystore to each server folder and copy cacerts to all servers and clients folder.
        */
        handler.MoveRequiredFilesFromTempToCertDir(certMap, parser);

        handler.generateConfFile4SMF5(certMap, parser);

        return true;
    }

    private boolean configureEnvForCertGeneration(Map<String, Object> certMap, F5GenParamParser parser, F5CertHandler handler) {
        List<CertPropsBean> list = (List<CertPropsBean>) certMap.get(CertParamTemplate.MAP_KEY_4_CERTPARAMLIST);
        return handler.prepareDirectories4Cert(list, parser)
                && handler.prepareOpenSSLEnv()
                && handler.prepareJavaKeyStoreEnv(parser);
    }

    public boolean handTemplateFileRequest(F5CertHandler handler) {
        boolean rtn = handler.createPropertyFileTemplate(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_F5_CERT_PROPS_FILE_TEMPLATE);
        if (rtn) {
            logger.printToConsole("The template named "
                    + CertParamTemplate.SM_F5_CERT_PROPS_FILE_TEMPLATE
                    + " has been created successfully, please find it under "
                    + FileUtil.getJarCurrentPath());
        } else {
            logger.printToConsole("Failed to create the template file named "
                    + CertParamTemplate.SM_F5_CERT_PROPS_FILE_TEMPLATE
                    + " under "
                    + FileUtil.getJarCurrentPath());
        }
        return rtn;
    }

    public void showF5HelpMessage() {
        String[] descArray = new String[4];
        descArray[0] = "gen -apache [OPTION]...";
        descArray[1] = "Generate certificates used to configure SSL in Apache:";
        descArray[2] = "Options:";
        descArray[3] = "Use \"gen -help\" for all available commands";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-kt", "Keep temp folder");
        paramMap.put("-config", "Specify the configuration file");
        paramMap.put("-template", "Generate a template configuration file");

        CertUtil.showSecondLevelHelpMessage(descArray, paramMap);
    }

}
