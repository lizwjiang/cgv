package org.g4.certificate.checker;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A property file used to provided all the data that is used to generate all f5 related certificates.
 * Before the data is used, need to validate them based on some rules.
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class F5PropsRuleChecker extends PropsRuleChecker {
    static CertLogger logger = CertLogger.getLogger(F5PropsRuleChecker.class.getName());

    public static boolean validate(Map<String, String> paramMap, boolean isOffloading) {
        return validateKeywords(paramMap, isOffloading) &&
                validateList(paramMap) &&
                validateDName(paramMap, isOffloading);
    }

    /**
     * There are some hardcoded keywords in TSO property file
     * such as server.list, client.list, loadbalancer, dname.type
     *
     * @param paramMap
     * @return
     */
    private static boolean validateKeywords(Map<String, String> paramMap, boolean isOffloading) {
        List<String> list = new ArrayList<String>();
        list.add(CertParamTemplate.PARAMETER_CLIENT_LIST);
        list.add(CertParamTemplate.PARAMETER_DNAME_TYPE);
        list.add(CertParamTemplate.PARAMETER_CA_COMMON_NAME);
        list.add(CertParamTemplate.PARAMETER_F5_COMMON_NAME);
        list.add(CertParamTemplate.PARAMETER_CA_ROOT_PASS);
        if (!isOffloading) {
            list.add(CertParamTemplate.PARAMETER_SERVER_COMMON_NAME);
        }
        String[] paramArray = new String[list.size()];
        list.toArray(paramArray);

        return validateKeyWords(paramMap, paramArray);
    }

    /**
     * validate the server list and client list, the rules should be
     * check the fqdn. For example, if server.list=server1, there must be a property named server.server1.fqdn
     *
     * @param paramMap the map object that stores all the properties and values from property file
     * @return false if the validation fails
     */
    private static boolean validateList(Map<String, String> paramMap) {
        String[] suffixArray = new String[]{CertParamTemplate.PARAMETER_SUFFIX_FQDN};

        return validateNullAndDuplicated(paramMap, CertParamTemplate.PARAMETER_CLIENT_LIST) &&
                validateNullAndDuplicated4ChildItems(paramMap,
                        CertParamTemplate.PARAMETER_CLIENT_LIST,
                        CertParamTemplate.PARAMETER_PREFIX_CLIENT,
                        suffixArray);
    }

    /**
     * # 0: global all clients, F5 and servers use the same DName including CA
     * # 1: all clients, F5 and servers use the same DName
     * # 2: servers and clients use the same DName, but f5 uses the different DName.
     * # 3: clients, F5 and servers use the same DName respectively
     * # Note, if dname.type is not equal to 0, the DName for CA must be specified
     * #       if SSL offloading, the DName of servers are not required, specifying 2 or 3 will get the same result
     *
     * @param paramMap
     * @return
     */
    public static boolean validateDName(Map<String, String> paramMap, boolean isOffloading) {
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
        if (dnameTypeValue == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_GLOBAL) {
            isGlobal = true;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_GLOBAL))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_CLIENT_F5_SERVER) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT_F5_SERVER))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_CLIENT_SERVER) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER))
                return false;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_F5))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_F5_DNAME_TYPE_SEP) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT))
                return false;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_F5))
                return false;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_SERVER))
                return false;
        } else {
            logger.printToConsole("Invalid value of dname.type, the correct one should be one of 0,1,2 and 3");
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
