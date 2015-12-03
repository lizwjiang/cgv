package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The parser for the parameters
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public abstract class ParameterParser {
    CertLogger logger = CertLogger.getLogger(ParameterParser.class.getName());

    private final String helpParam = "-h,-help";
    protected String[] helpParamArray = new String[]{"-h", "-help"};

    private boolean help;

    public void initialAnalysis(String[] args) {
        for (int i = 0; i < args.length; i++) {
            isHelpFromCommands(args);
        }
    }

    public boolean analyzeParams(String[] args, String[] childParamArray) {
        if (args != null) {
            isHelpFromCommands(args);
        }
        return true;
    }

    // detect whether input parameter contains duplicate data
    public boolean existDuplicateParameter(String[] inputParams) {
        // get all paratmer(start with -) from input parameter array
        List<String> parametersArr = new ArrayList<String>();
        Set<String> parameterSet = new HashSet<String>();

        for (String inputParam : inputParams)
            if (inputParam.startsWith("-")) // string with "-" is parameter key
            {
                parametersArr.add(inputParam);
                parameterSet.add(inputParam);
            }

        // if array size > set size, it means there are 2 parameter string with same hashcode, so there is duplicate parameter
        return parametersArr.size() > parameterSet.size();
    }


    /**
     * Check if all the arguments are valid
     *
     * @param args       the arguments put in command line
     * @param paramArray all valid arguments
     * @return
     */
    public boolean isInvalidParameter(String[] args, String[] paramArray) {
        boolean isInvalid = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith(CertParamTemplate.CERT_PARAMETER_PREFIX) && !CertUtil.isInScope(args[i], paramArray)) {
                isInvalid = true;
                break;
            }
        }
        return isInvalid;
    }

    /**
     * Some validation needs to be done by getting all valid parameters for an operation like TSO certificate generation.
     * Some common parameters exist in parent class,To get all when calling the method from child,
     * need to send all parameters of child class to the method of parent class,
     * and then merge the parameters of parent class and child class
     *
     * @param parentParamArray
     * @param childParamArray
     * @return
     */
    public String[] addParamsOfChildClass(String[] parentParamArray, String[] childParamArray) {
        List<String> list = new ArrayList<String>();

        for (int i = 0; i < parentParamArray.length; i++) {
            list.add(parentParamArray[i]);
        }

        for (int i = 0; i < childParamArray.length; i++) {
            list.add(childParamArray[i]);
        }
        String[] retArray = new String[list.size()];
        list.toArray(retArray);
        return retArray;
    }

    /**
     * Check if the parameter which should follow the value is valid.
     * The rules for validation should be
     * 1. it can not be the last one as the value should be specified for it. e.g. CertGen -kt -config
     * 2. it can not be followed another parameters e.g. -config -t
     *
     * @param i
     * @param args
     * @param paramArray
     * @return
     */
    protected boolean validateParam(int i, String[] args, String[] paramArray) {
        /*
        if the current parameter is the last element of the array, which means no value is specified for that, need to return false.
        if a parameter is following another parameter like -d -client_keystorePass, the validation should not pass
        */
        if (i == args.length - 1 || CertUtil.isInScope(args[i + 1], paramArray)) {
            logger.printToConsole("Incorrect value is specified for the command option : " + args[i]);
            return false;
        }
        return true;
    }

    public List<Object> validateParamWithValue(int i, String[] args, String[] paramArray) {
        List<Object> list = new ArrayList<Object>();
        boolean isPass = validateParam(i, args, paramArray);
        if (!isPass)
            return null;

        list.add(args[i + 1]);
        if (i + 1 <= args.length - 1) {
            i++;
        }
        list.add(i);
        return list;
    }

    /**
     * Some arguments can not be put in command line at the same time.
     * for example, -local_crl -download_cr
     *
     * @param args
     * @param exclusiveArray
     * @return
     */
    public boolean isParamsExclusive(String[] args, String[] exclusiveArray) {
        int count = 0;
        for (int i = 0; i < args.length; i++) {
            if (CertUtil.isInScope(args[i], exclusiveArray)) {
                count++;
            }
        }
        if (count > 1) {
            String tempStr = "";
            for (int i = 0; i < exclusiveArray.length; i++) {
                if (i != exclusiveArray.length - 1) {
                    tempStr += exclusiveArray[i] + ", ";
                } else {
                    tempStr += " and " + exclusiveArray[i];
                }
            }
            logger.printToConsole("Only one of  " + tempStr + " can be specified in command line");
            return false;
        } else {
            return true;
        }
    }

    /**
     * Some arguments don't have value. For these ones, need to validate.
     * The rules should be:
     * 1. check if the first argument starts with "-". If not, return false;
     * 2. check if some arguments have the values. if so, return false
     *
     * @param args
     * @param singleParams
     * @return
     */
    public boolean isSingleParam(String[] args, String[] singleParams) {
        if (!args[0].startsWith(CertParamTemplate.CERT_PARAMETER_PREFIX))
            return false;
        for (int i = 0; i < args.length; i++) {
            for (int j = 0; j < singleParams.length; j++) {
                if (singleParams[j].equalsIgnoreCase(args[i])) {
                    if (i < args.length - 1) {
                        String tempStr = args[i + 1];
                        if (!tempStr.startsWith(CertParamTemplate.CERT_PARAMETER_PREFIX)) {
                            logger.printToConsole("The " + args[i] + " command option should not have the value, please verify");
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    private void isHelpFromCommands(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if (CertUtil.isInScope(args[i], helpParam.split(","))) {
                this.help = true;
            }
        }
    }

    public boolean isHelp() {
        return help;
    }

    public String getHelpParam() {
        return this.helpParam;
    }

}
