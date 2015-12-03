package org.g4.certificate.auth.cac;

import org.g4.certificate.parser.CACCertAuthParamParser;

import java.util.ArrayList;
import java.util.List;

/**
 * The checker that is used to call registered rules and validate
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class RuleChecker {
    private List<Rule> rules = new ArrayList<Rule>();

    public void addRule(Rule r) {
        rules.add(r);
    }

    public void registerRules(CACCertAuthParamParser pp) {
        addRule(new ExpirationRule());
        if (pp.isLocalCRL()) {
            addRule(new LocalCRLRule());
        }
        if (pp.isOnlineCRLs()) {
            addRule(new OnlineCRLRule());
        }
        if (pp.isOcsp()) {
            addRule(new OCSPRule());
        }
        if (pp.isLdapCRL()) {
            addRule(new LDAPCRLRule());
        }
        if (pp.isSmartCard()) {
            addRule(new CertificateTypeRule());
        }
        if(pp.disableCRLCheck()){
            addRule(new DisableCRLRule());
        }
    }

    public RuleCheckResult check(CACCertAuthParamParser pp) {
        registerRules(pp);
        for (Rule rule : rules) {
            RuleCheckResult result = rule.validate(pp);
            if (!result.isPass()) {
                return result;
            }
        }
        return RuleCheckResult.TRUE;
    }
}
