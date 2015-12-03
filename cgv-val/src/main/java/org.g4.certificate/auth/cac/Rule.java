package org.g4.certificate.auth.cac;

import org.g4.certificate.parser.CACCertAuthParamParser;

/**
 * The interface of Rule
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public interface Rule {
    RuleCheckResult validate(CACCertAuthParamParser pp);
}
