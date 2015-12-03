package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;

/**
 * Handler that is used to handle parameters when TSO certificate generation
 * including parameters validation and analysis
 * CertGen -t -template -apache/tso/f5 -kt -conf c:\temp\cert.conf -jre_home c:\jdk1.7.0.25 -h
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class TSOGenParamParser extends CertGenParamParser {
    private CertLogger logger = CertLogger.getLogger(TSOGenParamParser.class.getName());
    private final String testParam = "-t";

    private boolean test;

    /**
     * The command should be like CertGen -Apache/TSO/F5 -kt -conf c:\myConfFile -t -jre_home C:\Program Files (x86)\Java\jdk1.7.0_51
     * Apache/TSO/F5    what kinds of certificates should be generated
     * kt               keep temp folder where some temp files are there
     * config           the config file that is used to generate certificates
     * t                all the certificates will be generated for testing. if it is specified, user just needs input client FQDN and server FQDN.
     *                  Also the certificates are only for a server and a client.
     * jre_home         JRE home that is specified in command line
     * template         generate a template file which contains all the properties and their values which are used to generate TSO certificates
     *
     * @param args
     */
    public boolean analyzeParams(String[] args) {
        String[] paramArray = new String[]{testParam};

        if (!super.analyzeParams(args, paramArray)) return false;
        if(!isSingleParam(args, paramArray)) return false;

        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equalsIgnoreCase(testParam)) {
                    this.test = true;
                }
            }
        }
        if(!isConfig() && !isTemplate() && !isTest()){
            String defaultConfFile = FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE;
            if (!FileUtil.isFile(defaultConfFile)) {
                logger.printToConsole("Can't find the configuration file named "
                        + CertParamTemplate.SM_TSO_CERT_PROPS_FILE
                        + " under "
                        + FileUtil.getJarCurrentPath());
                return false;
            }
            setConfFile(defaultConfFile);
        }

        return true;
    }

    public boolean isTest() {
        return test;
    }

}
