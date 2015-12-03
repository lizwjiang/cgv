package org.g4.certificate.auth.cac;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;

import java.io.DataInputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Validate user certificate with online CRL
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class OnlineCRLRule extends AbstractRule {
    CertLogger logger = CertLogger.getLogger(OnlineCRLRule.class.getName());

    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        CertPath cp = getCertPath(pp);
        if (cp == null) return RuleCheckResult.FALSE;

        // Load the root CA certificate
        Set<TrustAnchor> trustedCerts = getTrustedCerts(pp);
        if (trustedCerts == null) return RuleCheckResult.FALSE;

        List<X509CRL> crls = null;
        if (!CertUtil.isNull(pp.getOnlineCRL())) {
            crls = getOnlineCRLs(pp);
            if (crls == null)
                return RuleCheckResult.FALSE;
        } else {
            enableCRLDP();
        }

        PKIXParameters params = initPKIXParams(trustedCerts, crls, pp);
        RuleCheckResult result = validate(cp, params);

        return result;
    }

    public List<X509CRL> getOnlineCRLs(CACCertAuthParamParser pp) {
        List<X509CRL> crlList = new ArrayList<X509CRL>();

        String[] paths = pp.getOnlineCRL().split(CertParamTemplate.CERT_COMMA);
        for (short i = 0; i < paths.length; i++) {
            X509CRL crl = getOnlineCRL(paths[i], pp);
            if (crl != null) {
                crlList.add(crl);
            } else {
                return null;
            }
        }
        return crlList;
    }

    public X509CRL getOnlineCRL(String url, CACCertAuthParamParser pp) {
        DataInputStream is = null;
        try {
            CertificateFactory cf = getCertificateFactory(pp);
            URLConnection conn = new URL(url).openConnection();
            conn.setDoInput(true);
            conn.setUseCaches(false);
            is = new DataInputStream(conn.getInputStream());
            X509CRL crl = (X509CRL) cf.generateCRL(is);
            return crl;
        } catch (Exception e) {
            logger.printToConsoleAndLogFile("Fail to get CRL from " + url, e);
        } finally {
            CertUtil.closeInputStream(is);
        }
        return null;
    }

    public void enableCRLDP() {
        String vmname = System.getProperty("java.vm.name");
        if (vmname != null && vmname.startsWith("IBM")) {
            // If running within IBM JRE
            System.setProperty("com.ibm.security.enableCRLDP", "true");
        } else {
            System.setProperty("com.sun.security.enableCRLDP", "true");
        }
    }
}
