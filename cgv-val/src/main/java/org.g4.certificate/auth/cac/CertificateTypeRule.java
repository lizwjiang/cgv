package org.g4.certificate.auth.cac;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.ExceptionUtils;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Verify if the user certificate is from smart card
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class CertificateTypeRule extends AbstractRule {
    CertLogger logger = CertLogger.getLogger(CertificateTypeRule.class.getName());
    public static final String SMART_CARD_LOGON_OID = "1.3.6.1.4.1.311.20.2.2";

    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        try {
            X509Certificate userCert = getCertFromFile(pp.getUserCert());
            List<String> usageList = userCert.getExtendedKeyUsage();
            if (usageList != null && usageList.contains(SMART_CARD_LOGON_OID)) {
                return RuleCheckResult.TRUE;
            } else {
                return new RuleCheckResult(false, "your certificate type is not smart card");
            }
        } catch (CertificateParsingException e) {
            logger.printToConsoleAndLogFile("Error happens when validate if the certificate is smart card, the root cause is"
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return RuleCheckResult.FALSE;
        }
    }
}
