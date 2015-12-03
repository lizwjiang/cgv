package org.g4.certificate.bean;

import java.io.Serializable;

/**
 * Use this bean class to collect all the data for keytool command
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class KeytoolBean implements Serializable {
    private String keyStoreAlias;
    private String keyStoreFile;
    private String reqCert;
    private String keyStorePass;
    private String certFile;
    private CertPropsBean certPropsBean;
    private boolean trustedClient = false;

    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public String getReqCert() {
        return reqCert;
    }

    public void setReqCert(String reqCert) {
        this.reqCert = reqCert;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public void setKeyStorePass(String keyStorePass) {
        this.keyStorePass = keyStorePass;
    }

    public String getCertFile() {
        return certFile;
    }

    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }

    public CertPropsBean getCertPropsBean() {
        return certPropsBean;
    }

    public void setCertPropsBean(CertPropsBean certPropsBean) {
        this.certPropsBean = certPropsBean;
    }

    public boolean isTrustedClient() {
        return trustedClient;
    }

    public void setTrustedClient(boolean trustedClient) {
        this.trustedClient = trustedClient;
    }
}
