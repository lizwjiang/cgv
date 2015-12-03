package org.g4.certificate.auth;

import org.g4.certificate.auth.cac.RuleCheckResult;
import org.g4.certificate.auth.cac.RuleChecker;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.handler.LoggingHandler;
import org.g4.certificate.handler.sso.SMTSOAuthHandler;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.parser.CertAuthParamParser;
import org.g4.certificate.parser.TSOCertAuthParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This should be able to validate three types of certificates - TSO, Apache and F5
 * The folder structure for TSO should be like
 * TSO_AUTH_CERTS (default value. user can specify another one)
 * |
 * |_Servers
 * |  |_server1.keystore
 * |  |_server2.keystore
 * |
 * |_Clients
 * |  |_client1.keystore
 * |  |_client2.keystore
 * |
 * |_cacerts
 * |
 * |_trustedclients.keystore
 *
 * @author : Johnson Jiang
 * @since 1.0
 */
public class CertAuth {
    static CertLogger logger = CertLogger.getLogger(CertAuth.class.getName());

    /**
     * The input parameters should be
     * -d The root path of all certificates need to be validated
     * -client_keystorePass The password of the keystore of client sertificate, the default value is clientkeystore
     * -server_keystorePass The password of the keystore of server certificate, the default value is serverkeystore
     * -ssl_trustedClientsPwd The password of the key store of trusted clients, the default value is trustedClients
     *
     * @param args
     */
    public static void main(String[] args) {
        logger.debug("The command called to generate certificates is: " + CertAuth.class.getName() + " " + LoggingHandler.getAllParmsInCommandLine(args));

        CertAuthParamParser ph = new CertAuthParamParser();
        ph.initialAnalysis(args);

        if (ph.isTSO()) {
            if (ph.isHelp()) {
                showTSOHelpMessage();
                return;
            }
            TSOCertAuthParamParser parser = new TSOCertAuthParamParser();
            if (!parser.analyzeParams(args))
                return;

            logger.printToConsole(CertParamTemplate.SYSTEM_PROMPT_START_HANDLING_MSG);
            new SMTSOAuthHandler().handleRequest(parser);
        } else if (ph.isCAC()) {
            if (ph.isHelp()) {
                showCACAuthHelpMessage();
                return;
            }

            CACCertAuthParamParser parser = new CACCertAuthParamParser();
            if (!parser.analyzeParams(args)) return;

            RuleChecker rc = new RuleChecker();
            RuleCheckResult rcr = rc.check(parser);
            if (!rcr.isPass()) {
                logger.printToConsole("Validation failed. " + (CertUtil.isNull(rcr.getMsg()) ? "" : "The root cause is " + rcr.getMsg()));
            } else {
                logger.printToConsole("No exception and error happen, the validation on certificates passed");
            }
        } else {
            if (ph.isHelp()) {
                showHelpMessage();
                return;
            }else{
                logger.printToConsole("One of -tso and -cac must be specified ");
            }
            logger.printToConsole("Use \"-help\" option to show all available commands");
        }
    }

    private static void enableSSLDebugInfo() {
        System.setProperty("javax.net.debug", "ssl,handshake");
    }

    private static void showTSOHelpMessage() {
        String[] descArray = new String[4];
        descArray[0] = "Auth -tso [OPTION]...";
        descArray[1] = "Validate certificates for trusted sign on:";
        descArray[2] = "Options:";
        descArray[3] = "Use \"Auth -help\" for all available commands";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-d", "specify the directory the certificates need to be validated");
        paramMap.put("-client_keystorePass", "password of client keystores");
        paramMap.put("-server_keystorePass", "password of server keystores");
        paramMap.put("-ssl_trustedClientsPwd", "password of keystore of trusted clients");

        CertUtil.showSecondLevelHelpMessage(descArray, paramMap, 25);
    }

    private static void showCACAuthHelpMessage() {
        String[] descArray = new String[4];
        descArray[0] = "Auth -cac [OPTION]...";
        descArray[1] = "Validate certificates for CAC:";
        descArray[2] = "Options:";
        descArray[3] = "Use \"Auth -help\" for all available commands";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-d", "specify the directory where the certificates need to be validated");
        paramMap.put("-user_cert", "user certificate");
        paramMap.put("-ca_cert", "CA's certificates");
        paramMap.put("-local_crl", "the path of the local CRL files");
        paramMap.put("-online_crl", "URL that identifies the location of the CRL");
        paramMap.put("-ocsp_server", "file path to OCSP Server CA certificate");
        paramMap.put("-ocsp_responder", "URL that identifies the location of the OCSP responder");
        paramMap.put("-smart_card_check", "check if the certificate type is smart card");
        paramMap.put("-disable_crl_check", "disable the CRL check");
        paramMap.put("-proxy_protocol", "the protocol of proxy");
        paramMap.put("-proxy_host", "proxy host");
        paramMap.put("-proxy_port", "proxy port");
        paramMap.put("-nonproxy_hosts", "non proxy hosts");

        CertUtil.showSecondLevelHelpMessage(descArray, paramMap);
    }

    private static void showHelpMessage() {
        String[] descArray = new String[3];
        descArray[0] = "Certificate Management Tool";
        descArray[1] = "Commands:";
        descArray[2] = "Use the \"auth -command_name -help\" for usage of command_name";

        Map<String, String> paramMap = new LinkedHashMap<String, String>();
        paramMap.put("-tso", "validate certificates of Trusted Sign On");
        paramMap.put("-cac", "validate certificates of CAC");

        CertUtil.showHelpMessage(descArray, paramMap);
    }
}
