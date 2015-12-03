package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;

/**
 * This is to parse all the arguments used for Apache certificate generation
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class ApacheGenParamParser extends CertGenParamParser {
    private CertLogger logger = CertLogger.getLogger(ApacheGenParamParser.class.getName());
    private final String clientReqParam = "-clientReq";

    private boolean clientReq;

    /**
     * The command should be like CertGen -Apache/TSO/F5 -kt -conf c:\myConfFile -t -jre_home C:\Program Files (x86)\Java\jdk1.7.0_51
     * Apache/TSO/F5    what kinds of certificates should be generated
     * kt               keep temp folder where some temp files are there
     * config           the config file that is used to generate certificates
     *                  Also the certificates are only for a server and a client.
     * jre_home         JRE home that is specified in command line
     * template         generate a template file which contains all the properties and their values which are used to generate TSO certificates
     * clientReq        generate client certificate signed by the same CA of server certificate
     *
     * @param args
     */
    public boolean analyzeParams(String[] args){
        String[] nonCommonParams = new String[]{clientReqParam};

        if (!super.analyzeParams(args, nonCommonParams)) return false;
        if(!isSingleParam(args, nonCommonParams)) return false;

        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equalsIgnoreCase(clientReqParam)) {
                    this.clientReq = true;
                    break;
                }
            }
        }

        // if not specifying the config file and the template is not required to generate,
        // need to check if there is default file in jar path
        if(!isConfig() && !isTemplate()){
            String defaultConfFile = FileUtil.getJarCurrentPath() + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE;
            if (!FileUtil.isFile(defaultConfFile)) {
                logger.printToConsole("Can't find the configuration file named "
                        + CertParamTemplate.SM_APACHE_CERT_PROPS_FILE
                        + " under "
                        + FileUtil.getJarCurrentPath());
                return false;
            }
            setConfFile(defaultConfFile);
        }
        return true;
    }

    public boolean isClientReq() {
        return clientReq;
    }
}
