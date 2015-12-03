package org.g4.certificate.auth.cac;

import org.g4.certificate.parser.CACCertAuthParamParser;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * The rule is used to check the expiration date
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class ExpirationRule extends AbstractRule {
    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        try {
            X509Certificate userCert = getCertFromFile(pp.getUserCert());
            userCert.checkValidity();
            return RuleCheckResult.TRUE;
        } catch (CertificateExpiredException certExp) {
            return new RuleCheckResult(false, "your certificate has expired");
        } catch (CertificateNotYetValidException e) {
            return new RuleCheckResult(false, "your certificate is not yet valid");
        }
    }
}
