package org.g4.certificate.gen;

import org.g4.certificate.controller.ApacheController;
import org.g4.certificate.controller.SMF5Controller;
import org.g4.certificate.controller.SMTSOController;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.LoggingHandler;
import org.g4.certificate.parser.ApacheGenParamParser;
import org.g4.certificate.parser.CertGenParamParser;
import org.g4.certificate.parser.F5GenParamParser;
import org.g4.certificate.parser.TSOGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The only entry to generate different types of certificates for different scenarios such as Trusted sign on, Apache and F5.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertGen {
    static CertLogger logger = CertLogger.getLogger(CertGen.class.getName());

    public static void main(String[] args) {
        logger.debug("The command called to generate certificates is: " + CertGen.class.getName() + " "
                + LoggingHandler.getAllParmsInCommandLine(args));

        CertGenParamParser ph = new CertGenParamParser();
        ph.initialAnalysis(args);

        if (ph.isTSO()) {
            TSOGenParamParser parser = new TSOGenParamParser();
            SMTSOController controller = new SMTSOController();

            if (ph.isHelp()) {
                controller.showTSOHelpMessage();
                return;
            }
            if (!parser.analyzeParams(args)) return;
            if (!controller.handleTSOCertGenRequest(parser)) return;
            if (!parser.isTemplate())
                logger.printToConsole("All the certificates have been generated, you can find them from "
                        + FileUtil.getJarCurrentPath()
                        + CertParamTemplate.CERT_ROOT_FOLDER
                        + CertParamTemplate.CERT_SLASH
                        + CertParamTemplate.CERT_TRUSTEDSIGNON_FOLDER);
        } else if (ph.isF5()) {
            F5GenParamParser parser = new F5GenParamParser();
            SMF5Controller controller = new SMF5Controller();
            if(ph.isHelp()){
                controller.showF5HelpMessage();
                return;
            }

            if(!parser.analyzeParams(args)) return;
            if(!controller.handF5CertGenRequest(parser)) return;
            if(!parser.isTemplate())
                logger.printToConsole("All the certificates have been generated, you can find them from "
                        + FileUtil.getJarCurrentPath()
                        + CertParamTemplate.CERT_ROOT_FOLDER
                        + CertParamTemplate.CERT_SLASH
                        + CertParamTemplate.CERT_F5_FOLDER);

        } else if (ph.isApache()) {
            ApacheGenParamParser parser = new ApacheGenParamParser();
            ApacheController controller = new ApacheController();

            if(ph.isHelp()){
                controller.showApacheHelpMessage();
                return;
            }
            if (!parser.analyzeParams(args)) return;
            if(!parser.analyzeParams(args)) return;
            if(!controller.handleApacheCertRequest(parser)) return;
            if (!parser.isTemplate())
                logger.printToConsole("All the certificates have been generated, you can find them from "
                        + FileUtil.getJarCurrentPath()
                        + CertParamTemplate.CERT_ROOT_FOLDER
                        + CertParamTemplate.CERT_SLASH
                        + CertParamTemplate.CERT_APACHE_FOLDER);
        } else {
            if (ph.isHelp()) {
                showHelpMessage();
                return;
            }
            logger.printToConsole("Use \"gen -help\" to show all available commands");
            return;
        }

    }

    private static void showHelpMessage() {
        String[] descArray = new String[3];
        descArray[0] = "Certificate Management Tool";
        descArray[1] = "Commands:";
        descArray[2] = "Use the \"gen -command_name -help\" for usage of command_name";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-tso", "Generate certificates for Trusted Sign On");
        paramMap.put("-apache", "Generate certificates for Apache");
        paramMap.put("-f5", "Generate certificates for F5 HWLB");

        CertUtil.showHelpMessage(descArray, paramMap);
    }
}
