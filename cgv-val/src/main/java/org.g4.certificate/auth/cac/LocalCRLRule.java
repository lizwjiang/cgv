package org.g4.certificate.auth.cac;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.ExceptionUtils;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Validate the user certificate with the local CRL
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class LocalCRLRule extends AbstractRule {
    private CertLogger logger = CertLogger.getLogger(LocalCRLRule.class.getName());

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

        List<X509CRL> crls = getLocalCRLs(pp);
        if (crls == null) {
            logger.printToConsole("Can't load the CRL files, please check " + pp.getCrls());
            return RuleCheckResult.FALSE;
        }

        PKIXParameters params = initPKIXParams(trustedCerts, crls, pp);
        RuleCheckResult result = validate(cp, params);

        return result;
    }

    private List<X509CRL> getLocalCRLs(CACCertAuthParamParser pp) {
        FileInputStream fis = null;
        List<X509CRL> crlList = new ArrayList<X509CRL>();
        String[] crlArray = pp.getCrlArray();


        for (int i = 0; i < crlArray.length; i++) {
            try {
                fis = new FileInputStream(new File(crlArray[i].trim()));
                CertificateFactory cf = getCertificateFactory(pp);
                X509CRL crl = (X509CRL) cf.generateCRL(fis);
                crlList.add(crl);
            } catch (Exception e) {
                logger.error("Error happens when getting CRL from "
                        + crlArray[i]
                        + ", the root cause is "
                        + ExceptionUtils.getRootCauseMessage(e), e);
                return null;
            } finally {
                CertUtil.closeInputStream(fis);
            }
        }
        return crlList;

    }

}
