package org.g4.certificate.checker;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class is to validate whether the property file is correct
 *
 * @author Peter Zhang
 * @version 1.0cl
 */
public class ApachePropsRuleChecker extends PropsRuleChecker {
    static CertLogger logger = CertLogger.getLogger(F5PropsRuleChecker.class.getName());

    public static boolean validate(Map<String, String> paramMap) {
        return validateKeywords(paramMap) &&
                validateDName(paramMap);
    }

    /**
     * There are some hardcoded keywords in Apache property file
     * such as server.fqdn, ca.common.name, client.common.name, dname.type
     *
     * @param paramMap
     * @return
     */
    private static boolean validateKeywords(Map<String, String> paramMap) {
        List<String> list = new ArrayList<String>();
        list.add(CertParamTemplate.PARAMETER_DNAME_TYPE);
        list.add(CertParamTemplate.PARAMETER_SERVER_FQDN);
        list.add(CertParamTemplate.PARAMETER_CA_COMMON_NAME);
        list.add(CertParamTemplate.PARAMETER_CLIENT_COMMON_NAME);

        String[] paramArray = new String[list.size()];
        list.toArray(paramArray);

        return validateKeyWords(paramMap, paramArray);
    }

    /**
     * # 0: global all Apache servers and CA use the same DName
     * # 1: server and CA use different Dname
     * # Note, if dname.type is not equal to 0, the DName for CA must be specified
     *
     * @param paramMap
     * @return
     */
    public static boolean validateDName(Map<String, String> paramMap) {
        String dnameType = paramMap.get(CertParamTemplate.PARAMETER_DNAME_TYPE);

        boolean isGlobal = false;
        if (CertUtil.isNull(dnameType)) {
            logger.printToConsole("No dname.type is specified in configuration file");
            return false;
        } else {
            if (!CertUtil.isNum(dnameType)) {
                logger.printToConsole(dnameType + " is not a valid dname type");
                return false;
            }
        }

        Integer dnameTypeValue = Integer.parseInt(dnameType);
        if (dnameTypeValue == CertParamTemplate.PARAMETER_APACHE_DNAME_TYPE_GLOBAL) {
            isGlobal = true;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_GLOBAL))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_APACHE_DNAME_TYPE_CLIENT_SERVER) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER))
                return false;
        } else {
            logger.printToConsole("Invalid value of dname.type, the correct one should be one of 0 or 1");
            return false;
        }

        if (!isGlobal) {
            //if not specify global as dname type, need to specify dname for CA.
            //That is to say, only when global is the dname type, CA's dname is not specified with "ca." prefix
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CA))
                return false;
        }
        return true;
    }

}
