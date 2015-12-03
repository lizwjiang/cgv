package org.g4.certificate.auth.cac;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CACCertAuthParamParser;
import org.g4.certificate.utilities.ExceptionUtils;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

/**
 * Validate user certificate with the CRL from LDAP
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class LDAPCRLRule extends AbstractRule {
    CertLogger logger = CertLogger.getLogger(LDAPCRLRule.class.getName());

    public RuleCheckResult validate(CACCertAuthParamParser pp) {
        CertPath cp = getCertPath(pp);
        if (cp == null) return RuleCheckResult.FALSE;

        // Load the root CA certificate
        Set<TrustAnchor> trustedCerts = getTrustedCerts(pp);
        if (trustedCerts == null) return RuleCheckResult.FALSE;

        List<X509CRL> crls = new ArrayList<X509CRL>();
        X509CRL crl = getCRLFromLDAP(pp.getLdapURL());
        if (crl == null) {
            return RuleCheckResult.FALSE;
        } else {
            crls.add(crl);
        }

        PKIXParameters params = initPKIXParams(trustedCerts, crls, pp);

        return validate(cp, params);
    }

    private X509CRL getCRLFromLDAP(String ldapURL) {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);
        try {
            DirContext ctx = new InitialDirContext(env);
            Attributes avals = ctx.getAttributes("");
            Attribute aval = avals.get("certificateRevocationList;binary");

            byte[] val = (byte[]) aval.get();
            if ((val == null) || (val.length == 0)) {
                logger.printToConsole("Can not download CRL from: " + ldapURL);
                return null;
            } else {
                InputStream inStream = new ByteArrayInputStream(val);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) cf.generateCRL(inStream);
                return crl;
            }
        } catch (Exception e) {
            logger.printToConsoleAndLogFile("Error happens when getting CRL from "
                    + ldapURL
                    + ". The root cause is "
                    + ExceptionUtils.getRootCauseMessage(e), e);
        }
        return null;
    }
}
