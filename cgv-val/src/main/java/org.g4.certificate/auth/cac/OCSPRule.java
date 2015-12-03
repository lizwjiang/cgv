package org.g4.certificate.auth.cac;

import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.CertUtil;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Validate user certificate with OCSP
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class OCSPRule extends AbstractRule {
    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        if (pp.isProxy()) setProxy(pp);

        CertPath cp = getCertPath(pp);
        if (cp == null)
            return RuleCheckResult.FALSE;

        X509Certificate[] rootCACerts = initRootCert(pp.getCAArray());

        // Load the root CA certificate
        Set<TrustAnchor> trustedCerts = getTrustedCerts(pp);
        if (trustedCerts == null)
            return RuleCheckResult.FALSE;

        Set<X509Certificate> crls = getCRLsFromOCSP(rootCACerts, pp.getOcspServerPath());
        if (crls == null)
            return RuleCheckResult.FALSE;

        PKIXParameters params = initPKIXParams(trustedCerts, crls, pp.disableCRLCheck());

        Security.setProperty("ocsp.enable", "true");
        if (!CertUtil.isNull(pp.getOcspResponderURL())) {
            Security.setProperty("ocsp.responderURL", pp.getOcspResponderURL());
        }

        RuleCheckResult result = validate(cp, params);
        if (pp.isProxy()) removeProxy(pp);

        return result;
    }

    public Set<X509Certificate> getCRLsFromOCSP(X509Certificate[] rootCACerts, String ocspServerCertPath) {
        X509Certificate ocspCert;
        if (CertUtil.isNull(ocspServerCertPath)) {
            ocspCert = rootCACerts[0];
        } else {
            ocspCert = getCertFromFile(ocspServerCertPath);
        }

        Set<X509Certificate> certSet = new HashSet<X509Certificate>();
        certSet.add(ocspCert);

        return certSet;
    }

    public void removeProxy(CACCertAuthParamParser pp) {
        Properties prop = System.getProperties();
        prop.remove(pp.getProtocol().toLowerCase() + ".proxyHost");
        prop.remove(pp.getProtocol().toLowerCase() + ".proxyPort");
        prop.remove(pp.getProtocol().toLowerCase() + ".nonProxyHosts");
    }

    /**
     * set the proxy only when the connection request to OCSP server can not be sent out without proxy
     *
     * @param pp
     */
    public void setProxy(CACCertAuthParamParser pp) {
        Properties prop = System.getProperties();
        prop.setProperty(pp.getProtocol().toLowerCase() + ".proxyHost", pp.getProxyHost());
        prop.setProperty(pp.getProtocol().toLowerCase() + ".proxyPort", pp.getProxyPort());
        if (!CertUtil.isNull(pp.getNonProxyHosts())) {
            prop.setProperty(pp.getProtocol().toLowerCase() + ".nonProxyHosts", pp.getNonProxyHosts());
        }
    }
}
