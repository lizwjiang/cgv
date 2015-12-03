package org.g4.certificate.auth.cac;

import java.security.cert.CertPathValidatorResult;

/**
 * The result after checking the rules
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class RuleCheckResult {
    private boolean pass;
    private String msg;
    public static RuleCheckResult FALSE = new RuleCheckResult(false);
    public static RuleCheckResult TRUE = new RuleCheckResult(true);
    private CertPathValidatorResult validatorResult;

    public RuleCheckResult(boolean pass) {
        this(pass, "");
    }

    public RuleCheckResult(boolean pass, String msg) {
        this.pass = pass;
        this.msg = msg;
    }

    public boolean isPass() {
        return pass;
    }

    public void setPass(boolean pass){
        this.pass = pass;
    }

    public String getMsg() {
        return msg;
    }

    public CertPathValidatorResult getValidatorResult() {
        return validatorResult;
    }

    public void setValidatorResult(CertPathValidatorResult validatorResult) {
        this.validatorResult = validatorResult;
    }
}
