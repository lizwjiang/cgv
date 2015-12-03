package org.g4.certificate.auth.cac;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.ExceptionUtils;

import java.io.FileInputStream;
import java.lang.reflect.Constructor;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Abstract class for Rule interface
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public abstract class AbstractRule implements Rule {
    CertLogger logger = CertLogger.getLogger(AbstractRule.class.getName());
    private static boolean hasRegisteredJCE = false;
    public static final String X509 = "X.509";
    public static final String PKIX = "PKIX";

    public abstract RuleCheckResult validate(CACCertAuthParamParser pp);

    protected CertPath getCertPath(CACCertAuthParamParser pp) {
        CertificateFactory cf;
        CertPath cp = null;

        try {
            cf = CertificateFactory.getInstance("X.509");
            cp = cf.generateCertPath(Arrays
                    .asList(new X509Certificate[]{getCertFromFile(pp.getUserCert())}));
        } catch (CertificateException e) {
            logger.error("Error happens when getting certificate from "
                    + pp.getUserCert()
                    + ". The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return null;
        }
        return cp;
    }

    protected Set<TrustAnchor> getTrustedCerts(CACCertAuthParamParser pp) {
        // Load the root CA certificate
        X509Certificate[] rootCACerts = initRootCert(pp.getCAArray());
        if (rootCACerts == null)
            return null;

        Set<TrustAnchor> trustedCerts = initTrustedCerts(rootCACerts);
        return trustedCerts;
    }

    protected RuleCheckResult validate(CertPath cp, PKIXParameters params) {
        CertPathValidator cpv;
        RuleCheckResult result = RuleCheckResult.TRUE;
        try {
            cpv = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult cpvr = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
            result.setValidatorResult(cpvr);
        } catch (Exception e) {
            // Here if the exception is captured, we can think the validation on the certificates didn't pass
            logger.error("The validation on the certificates failed, the root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return new RuleCheckResult(false, ExceptionUtils.getRootCauseMessage(e).toLowerCase());
        }
        return result;
    }

    protected PKIXParameters initPKIXParams(Set<TrustAnchor> trustedCerts, List<X509CRL> crls, CACCertAuthParamParser pp) {
        PKIXParameters params = null;
        try {
            params = new PKIXParameters(trustedCerts);
            // Only when two conditions are satisfied, the CRLs can be put in PKIXParameters
            // 1. allow to check CRL
            // 2. CRLs are specified in command line
            if (!pp.disableCRLCheck() && crls != null) {
                params.setRevocationEnabled(true);
                if (!CertUtil.isNull(pp.getProviderName())) {
                    //if fail to initialize provider, return null directly.
                    if (!initProvider(pp))
                        return null;
                    params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls), pp.getProviderName()));
                } else {
                    params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));
                }
            } else {
                params.setRevocationEnabled(false);
            }
        } catch (Exception e) {
            logger.error("Error happens when initializing PKIX parameters, the root cause is"
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return null;
        }
        return params;
    }

    protected PKIXParameters initPKIXParams(Set<TrustAnchor> trustedCerts, Set<X509Certificate> certSet, boolean disableCRLCheck) {
        PKIXParameters params = null;
        try {
            params = new PKIXParameters(trustedCerts);
            if (!disableCRLCheck) {
                params.setRevocationEnabled(true);
                params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(certSet)));
            } else {
                params.setRevocationEnabled(false);
            }
        } catch (Exception e) {
            logger.error("Error happens when initializing PKIX parameters, the root cause is"
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return null;
        }
        return params;
    }

    protected X509Certificate[] initRootCert(String[] caPaths) {
        ;
        X509Certificate[] certs = new X509Certificate[caPaths.length];
        for (int i = 0; i < caPaths.length; i++) {
            X509Certificate cert = getCertFromFile(caPaths[i].trim());
            if (cert != null) {
                certs[i] = cert;
            } else {
                return null;
            }
        }
        return certs;
    }

    private Set<TrustAnchor> initTrustedCerts(X509Certificate[] rootCACerts) {
        HashSet<TrustAnchor> trustedCerts = new HashSet<TrustAnchor>(rootCACerts.length);
        for (X509Certificate cert : rootCACerts) {
            trustedCerts.add(new TrustAnchor(cert, null));
        }
        return trustedCerts;
    }


    public X509Certificate getCertFromFile(String certFile) {
        CertificateFactory cf;
        FileInputStream fis = null;

        try {
            cf = CertificateFactory.getInstance(X509);
            fis = new FileInputStream(certFile);
            return (X509Certificate) cf.generateCertificate(fis);
        } catch (Exception e) {
            logger.error("Error happens when getting certificate from "
                    + certFile
                    + ". The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return null;
        } finally {
            CertUtil.closeInputStream(fis);
        }
    }

    private boolean initProvider(CACCertAuthParamParser pp) {
        Provider provider = getProvider(pp.getProviderClass());
        return addJCEProvider(provider, pp.getProviderName());
    }

    private Provider getProvider(String clazzName) {
        Provider ret;
        try {
            Class clazz = Class.forName(clazzName);
            Constructor con = clazz.getConstructor(new Class[0]);
            ret = (Provider) con.newInstance(new Object[0]);
        } catch (Exception e) {
            logger.error("Error happens when initializing provider from class "
                    + clazzName
                    + ". The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
            return null;
        }

        return ret;
    }

    private static boolean addJCEProvider(Provider provider, String providerName) {
        Security.removeProvider(providerName);

        int position = Security.insertProviderAt(provider, 1);
        return position == 1;
    }

    public CertificateFactory getCertificateFactory(CACCertAuthParamParser pp) throws CertificateException {
        CertificateFactory ret;
        if (!CertUtil.isNull(pp.getProviderName()) && initProvider(pp)) {
            try {
                ret = CertificateFactory.getInstance(X509, pp.getProviderName());
            } catch (NoSuchProviderException e) {
                ret = CertificateFactory.getInstance(X509);
            }
        } else {
            ret = CertificateFactory.getInstance(X509);
        }

        return ret;
    }
}
