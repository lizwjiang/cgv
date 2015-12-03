package org.g4.certificate.checker;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.Map;

/**
 * Before getting all the parameters from property file to generate required certificates of TSO,
 * need to validate all the parameters in it.
 * <p/>
 * The rules for validation on parameters should be
 * 1. should be values at least loadbalancer should be there for server.list
 * 2. duplication check. for example, for server.list, there should not be two same servers.
 * 3. check the fqdn. For example, if server.list=server1, there must be a property named server.server1.fqdn
 * 4. check the dname according the type
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class TSOPropsRuleChecker extends PropsRuleChecker {
    static CertLogger logger = CertLogger.getLogger(TSOPropsRuleChecker.class.getName());

    public static boolean validate(Map<String, String> paramMap) {

        return validateKeywords(paramMap) &&
                validateList(paramMap) &&
                validateLoadBalancer(paramMap) &&
                validateDName(paramMap);
    }

    /**
     * There are some hardcoded keywords in TSO property file
     * such as server.list, client.list, loadbalancer, dname.type
     *
     * @param paramMap
     * @return
     */
    private static boolean validateKeywords(Map<String, String> paramMap) {
        String[] paramArray = new String[]{
                CertParamTemplate.PARAMETER_SERVER_LIST,
                CertParamTemplate.PARAMETER_CLIENT_LIST,
                CertParamTemplate.PARAMETER_DNAME_TYPE,
                CertParamTemplate.PARAMETER_CA_COMMON_NAME
        };

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

        return validateNullAndDuplicated(paramMap, CertParamTemplate.PARAMETER_SERVER_LIST) &&
                validateNullAndDuplicated(paramMap, CertParamTemplate.PARAMETER_CLIENT_LIST) &&
                validateNullAndDuplicated4ChildItems(paramMap,
                        CertParamTemplate.PARAMETER_SERVER_LIST,
                        CertParamTemplate.PARAMETER_PREFIX_SERVER,
                        suffixArray) &&
                validateNullAndDuplicated4ChildItems(paramMap,
                        CertParamTemplate.PARAMETER_CLIENT_LIST,
                        CertParamTemplate.PARAMETER_PREFIX_CLIENT,
                        suffixArray);

    }

    /**
     * In property file, the keyword called loadbalancer should be hardcoded for server.list property
     *
     * @param paramMap
     * @return
     */
    public static boolean validateLoadBalancer(Map<String, String> paramMap) {
        String server_list = paramMap.get(CertParamTemplate.PARAMETER_SERVER_LIST);
        String[] serverArray = server_list.split(",");
        for (int i = 0; i < serverArray.length; i++) {
            if (serverArray[i].equalsIgnoreCase(CertParamTemplate.PARAMETER_LOADBALANCER))
                return true;
        }
        logger.printToConsole("No loadbalancer is specified in server.list");
        return false;
    }

    /**
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
        if (dnameTypeValue == CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL) {
            isGlobal = true;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_GLOBAL))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER))
                return false;
        } else if (dnameTypeValue == CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP) {
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_SERVER))
                return false;
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT))
                return false;
        } else {
            logger.printToConsole("Invalid value of dname.type, the correct one should be one of 0,1,2 and 3");
            return false;
        }

        if (!isGlobal) {
            //if not specify global as dname type, need to specify dname for CA.
            //That is to say, only when global is the dname type, CA's dname is not specified with ca. format
            if (!isValidDName(paramMap, CertParamTemplate.PARAMETER_PREFIX_CA))
                return false;
        }
        return true;
    }

}
