package org.g4.certificate.auth.cac;

import org.g4.certificate.parser.CACCertAuthParamParser;

import java.security.cert.CertPath;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Set;

/**
 * This rule is executed when only the CRL check is not required.
 * That is to say the option "-disable_crl_check" is specified in command line
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class DisableCRLRule extends AbstractRule {
    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        CertPath cp = getCertPath(pp);
        if (cp == null) {
            logger.printToConsole("Can't load user certificate, please check " + pp.getUserCert());
            return RuleCheckResult.FALSE;
        }

        // Load the root CA certificate
        Set<TrustAnchor> trustedCerts = getTrustedCerts(pp);
        if (trustedCerts == null) {
            logger.printToConsole("Can't parse the trusted CA certificates, please check " + pp.getRootCerts());
            return RuleCheckResult.FALSE;
        }

        PKIXParameters params = initPKIXParams(trustedCerts, new ArrayList(), pp);
        RuleCheckResult result = validate(cp, params);

        return result;
    }
}
