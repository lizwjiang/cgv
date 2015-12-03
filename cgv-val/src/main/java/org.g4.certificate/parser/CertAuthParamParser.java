package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;

/**
 * Parameter parser for certificate validation
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class CertAuthParamParser extends ParameterParser {
    private CertLogger logger = CertLogger.getLogger(CertAuthParamParser.class.getName());
    private final String tsoParam = "-tso";
    private final String cacParam = "-cac";

    private boolean tso;
    private boolean cac;

    public void initialAnalysis(String[] args) {
        super.initialAnalysis(args);
        for (int i = 0; i < args.length; i++) {
            if (args[i].equalsIgnoreCase(tsoParam)) {
                this.tso = true;
            } else if (args[i].equalsIgnoreCase(cacParam)) {
                this.cac = true;
            }
        }
    }

    public boolean analyzeParams(String[] args, String[] childParamArray) {
        String[] helpArray = getHelpParam().split(CertParamTemplate.CERT_COMMA);
        String[] parentParamArray = new String[]{tsoParam, helpArray[0], helpArray[1], cacParam};
        String[] paramArray = addParamsOfChildClass(parentParamArray, childParamArray);

        super.analyzeParams(args, paramArray);

        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equalsIgnoreCase(tsoParam)) {
                    this.tso = true;
                } else if (args[i].equalsIgnoreCase(cacParam)) {
                    this.cac = true;
                }
            }
        }

        if(tso && cac){
            logger.printToConsole("Only one of TSO and CAC can be specified ");
            return false;
        }
        if (existDuplicateParameter(args)) {
            logger.printToConsole("There are duplicated input parameters, please correct");
            return false;
        }

        if (isInvalidParameter(args, paramArray)) {
            logger.printToConsole("There are invalid parameters in command line, please verify");
            return false;
        }
        return true;
    }

    public boolean isTSO(){
        return tso;
    }

    public boolean isCAC(){
        return cac;
    }
}
