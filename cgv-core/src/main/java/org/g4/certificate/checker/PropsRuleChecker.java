package org.g4.certificate.checker;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.util.Map;

/**
 * Get the data from a property file and apply some rules to validate
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public abstract class PropsRuleChecker {
    private static CertLogger log = CertLogger.getLogger(PropsRuleChecker.class.getName());

    /**
     * Validate some keywords.
     *
     * @param paramMap
     * @param keyWords
     * @return
     */
    public static boolean validateKeyWords(Map<String, String> paramMap, String[] keyWords) {
        for (int i = 0; i < keyWords.length; i++) {
            String msg = "Not specify " + keyWords[i] + " parameter";
            if (isNull(paramMap, keyWords[i], msg))
                return false;
        }
        return true;
    }


    public static boolean validateNullAndDuplicated(Map<String, String> paramMap, String key) {
        String value = paramMap.get(key);

        if (CertUtil.isNull(value)) {
            log.printToConsole("Need to specify values for " + key);
            return false;
        }

        String[] strArray = value.split(CertParamTemplate.CERT_COMMA);
        for(int i = 0; i< strArray.length; i++){
            if(CertUtil.isNull(strArray[i])){
              log.printToConsole("There is null value for " + key);
                return false;
            }
        }

        if (CertUtil.isDuplicated(strArray)) {
            log.printToConsole("There are duplicated values on " + key);
            return false;
        }
        return true;
    }

    /**
     * check if the the value of child item is not specified
     * E.g. server.list=server1,server2, there should be value for two child items:
     * server.server1.fqdn=<actual value> and server.server2.fqdn=<actual value>
     *
     * Also check the duplicated values for child items. E.g. server.list=server1,server2
     * if the child items are defined as below
     * server.server1.fqdn=idmvm01
     * server.server2.fqdn=idmvm01
     *
     * The validation will fail.
     * @param paramMap
     * @param key
     * @param prefix
     * @param suffixArray
     * @return
     */
    public static boolean validateNullAndDuplicated4ChildItems(Map<String, String> paramMap, String key, String prefix, String[] suffixArray) {
        String value = paramMap.get(key);
        String[] strArray = value.split(CertParamTemplate.CERT_COMMA);

        for(int i = 0; i < suffixArray.length; i++){
            String[] checkArray = new String[strArray.length];
            for(int j = 0; j < strArray.length; j++){
                String strKey = prefix + "." + strArray[j].trim() + "." + suffixArray[i];
                String strValue = paramMap.get(strKey);
                checkArray[j] = strValue;

                if (CertUtil.isNull(strValue)) {
                    log.printToConsole("There is no value for property : " + strKey);
                    return false;
                }
            }

            if(CertUtil.isDuplicated(checkArray)){
                log.printToConsole("Duplicated values are specified in " + prefix + ".<" + prefix + ">." + suffixArray[i]);
                return false;
            }
        }
        return true;
    }

    public static boolean isValidDName(Map<String, String> paramMap, String prefix) {
        String msg = "Not specify " + prefix + "." + CertParamTemplate.PARAMETER_DNAME_OU + " parameter";
        if (isNull(paramMap, prefix + "." + CertParamTemplate.PARAMETER_DNAME_OU, msg))
            return false;

        msg = "Not specify " + prefix + "." + CertParamTemplate.PARAMETER_DNAME_O + " parameter";
        if (isNull(paramMap, prefix + "." + CertParamTemplate.PARAMETER_DNAME_O, msg))
            return false;

        msg = "Not specify " + prefix + "." + CertParamTemplate.PARAMETER_DNAME_L + " parameter";
        if (isNull(paramMap, prefix + "." + CertParamTemplate.PARAMETER_DNAME_L, msg))
            return false;

        msg = "Not specify " + prefix + "." + CertParamTemplate.PARAMETER_DNAME_ST + " parameter";
        if (isNull(paramMap, prefix + "." + CertParamTemplate.PARAMETER_DNAME_ST, msg))
            return false;

        msg = "Not specify " + prefix + "." + CertParamTemplate.PARAMETER_DNAME_C + " parameter";
        if (isNull(paramMap, prefix + "." + CertParamTemplate.PARAMETER_DNAME_C, msg))
            return false;

        return true;
    }

    /**
     * Check if there is null value stored in a Map with the key.if so, print the error message.
     * @param paramMap
     * @param key
     * @param msg
     * @return
     */
    public static boolean isNull(Map<String, String> paramMap, String key, String msg) {
        String value = paramMap.get(key);
        if (CertUtil.isNull(value)) {
            log.printToConsole(msg);
            return true;
        }
        return false;
    }

}
