package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.io.Serializable;
import java.util.Map;

/**
 * This is used to handle the input parameters in command line including parameters analysis and validation.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertGenParamParser extends ParameterParser implements Serializable {
    CertLogger log = CertLogger.getLogger(CertGenParamParser.class.getName());
    protected final String apacheParam = "-apache";
    protected final String tsoParam = "-tso";
    protected final String f5Param = "-f5";
    protected final String keepTempParam = "-kt";
    protected final String confParam = "-config";
    protected final String jreHomeParam = "-jre_home";
    protected final String templateParam = "-template";
    private String slash = CertParamTemplate.CERT_SLASH;

    private boolean apache;
    private boolean tso;
    private boolean f5;
    private boolean keepTemp;
    private boolean config;
    private String confFile;
    private boolean jre;
    private String jreHome;
    private boolean template;

    private String[] singleParams = new String[]{
            apacheParam,
            tsoParam,
            f5Param,
            keepTempParam,
            templateParam,
            helpParamArray[0],
            helpParamArray[1]};

    /**
     * Analyze the arguments to get if the parameters are set : -apache, -tso, -f5, -h or -help
     *
     * @param args
     */
    public void initialAnalysis(String[] args) {
        super.initialAnalysis(args);
        for (int i = 0; i < args.length; i++) {
            if (args[i].equalsIgnoreCase(apacheParam)) {
                this.apache = true;
            } else if (args[i].equalsIgnoreCase(tsoParam)) {
                this.tso = true;
            } else if (args[i].equalsIgnoreCase(f5Param)) {
                this.f5 = true;
            }
        }
    }

    /**
     * Analyze the parameters in command line and apply some rules to validate.
     * The rules should be
     * Rule 1: one of Apache/TSO/F5 must be specified
     * Rule 2: only one of Apache/TSO/F5 can be specified. can not be more than 1.
     * Rule 3: check if there are some invalid parameters specified in command line
     * Rule 4: if config is specified, the following parameter should store the whole path including file
     * Rule 5: if jre_home is specified, the whole path of JRE should be followed
     * Rule 6: if config is specified, need to check the config file is valid or not.
     * otherwise, need to check if the default file is there.
     * Rule 7: if jre_home is specified, check if the specified one is a valid path
     *
     * @param args
     * @param childParamArray all the arguments of child class
     * @return
     */
    public boolean analyzeParams(String[] args, String[] childParamArray) {
        int certType = 0, confCount = 0, jreCount = 0;
        boolean isPass;
        String[] helpArray = getHelpParam().split(CertParamTemplate.CERT_COMMA);
        String[] parentParamArray = new String[]{apacheParam, tsoParam, f5Param,
                keepTempParam, confParam, jreHomeParam,
                helpArray[0], helpArray[1], templateParam};
        //this is parent class, there may be different parameters in child class
        //when this method is called to do validation, need all the parameters for TSO or F5
        //So need append the parameters of child class
        //parentParamArray is actually the common array
        String[] allAvailableParamArray = addParamsOfChildClass(parentParamArray, childParamArray);

        //here only checks if help parameter is specified in command line
        super.analyzeParams(args, allAvailableParamArray);

        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equalsIgnoreCase(apacheParam)) {
                    certType++;
                    this.apache = true;
                } else if (args[i].equalsIgnoreCase(tsoParam)) {
                    certType++;
                    this.tso = true;
                } else if (args[i].equalsIgnoreCase(f5Param)) {
                    certType++;
                    this.f5 = true;
                } else if (args[i].equalsIgnoreCase(keepTempParam)) {
                    this.keepTemp = true;
                } else if (args[i].equalsIgnoreCase(templateParam)) {
                    this.template = true;
                }
                if (args[i].equalsIgnoreCase(confParam)) {
                    confCount++;
                    this.config = true;
                    isPass = validateParam(i, args, allAvailableParamArray);

                    if (!isPass) {
                        return false;
                    } else {
                        this.confFile = args[i + 1].replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
                        if (i + 1 <= args.length - 1) {
                            i++;
                        }
                    }
                } else if (args[i].equalsIgnoreCase(jreHomeParam)) {
                    jreCount++;
                    this.jre = true;
                    isPass = validateParam(i, args, allAvailableParamArray);

                    if (!isPass) {
                        return false;
                    } else {
                        this.jreHome = args[i + 1].replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
                        if (i + 1 <= args.length - 1) {
                            i++;
                        }
                    }
                }
            }
        }
        if (certType == 0) {
            //no any one of Apache/TSO/F5 is specified
            log.printToConsole("One of Apache,TSO and F5 must be specified");
            return false;
        } else if (certType > 1) {
            //more than one cert types are specified
            log.printToConsole("Only one of Apache, TSO and F5 can be specified");
            return false;
        }

        if (confCount > 0) {
            if (CertUtil.isNull(confFile) || !FileUtil.isFile(confFile)) {
                log.printToConsole("Invalid configuration file is specified in the command line ");
                return false;
            }
        }

        if (jreCount > 0) {
            if (CertUtil.isNull(getJREHome()) || !FileUtil.isDir(getJREHome())) {
                log.printToConsole("Invalid JRE home is specified in command line");
                return false;
            } else {
                //Need to continue to check if the specified path is a valid JRE home
                if (!isValidJREHome(getJREHome()))
                    return false;
            }
        } else {
            //get the JRE home defined in ENV
            String jreHome = getEnvVar(CertParamTemplate.SYSTEM_ENV_JAVA_HOME);
            if (CertUtil.isNull(jreHome)) {
                log.printToConsole("No JAVA_HOME is specified in system environment variables, please set or use -jre_home to specify one in command line");
                return false;
            } else {
                if (!isValidJREHome(jreHome))
                    return false;
            }
        }

        // duplicate parameter is illegal
        if (existDuplicateParameter(args)) {
            log.printToConsole("Duplicate command options are in command line");
            return false;
        }

        if (isInvalidParameter(args, allAvailableParamArray)) {
            log.printToConsole("Invalid command options are in command line");
            return false;
        }

        return true;
    }

    /**
     * if an argument doesn't need a value, we call it single parameter like -tso, -t etc.
     *
     * @param args
     * @param childParams
     * @return
     */
    public boolean isSingleParam(String[] args, String[] childParams) {
        String[] tempSingleParams = addParamsOfChildClass(singleParams, childParams);
        return super.isSingleParam(args, tempSingleParams);
    }

    public boolean isValidJREHome(String javaHome) {
        javaHome += (!javaHome.endsWith(slash) ? slash : "");

        String jreHome;
        if (FileUtil.isFile(javaHome + "jre" + slash + "lib" + slash + "security" + slash + "cacerts")) {
            jreHome = javaHome + "jre" + slash;
        } else if (FileUtil.isFile(javaHome + "lib" + slash + "security" + slash + "cacerts")) {
            jreHome = javaHome;
        } else {
            log.printToConsole("No found some valid files like cacerts from the specified JRE, This might be a damaged JVM, please check");
            return false;
        }
        this.jreHome = jreHome;

        return true;
    }

    private String getEnvVar(String key) {
        Map m = System.getenv();
        return m.get(key) != null ? (String) m.get(key) : null;
    }

    public boolean isApache() {
        return apache;
    }

    public boolean isTSO() {
        return tso;
    }

    public boolean isF5() {
        return f5;
    }

    public boolean isKeepTemp() {
        return keepTemp;
    }

    public boolean isConfig() {
        return config;
    }

    public String getConfFile() {
        return confFile;
    }

    public void setConfFile(String confFile) {
        this.confFile = confFile;
    }

    public String getJREHome() {
        return jreHome;
    }

    public boolean isTemplate() {
        return template;
    }
}
