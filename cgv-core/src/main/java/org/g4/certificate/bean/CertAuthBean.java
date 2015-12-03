package org.g4.certificate.bean;

import org.g4.certificate.utilities.CertParamTemplate;

import java.io.Serializable;

/**
 * For certificate authentication, need to know some parameters such as server keystore, password of server keystore etc.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertAuthBean implements Serializable {
    private String serverKeyStore = "server.keystore";
    private String serverKeyStorePass = "serverkeystore";
    private String clientKeyStore;
    private String clientKeyStorePass = "clientkeystore";
    private String trustedClients = "trustedclients.keystore";
    private String trustedClientsStorePass = "trustedclients";
    private String transferMsg = CertParamTemplate.SOCKET_HELLO_SERVER;
    private boolean sslLog;

    public String getServerKeyStore() {
        return serverKeyStore;
    }

    public void setServerKeyStore(String serverKeyStore) {
        this.serverKeyStore = serverKeyStore;
    }

    public String getServerKeyStorePass() {
        return serverKeyStorePass;
    }

    public void setServerKeyStorePass(String serverKeyStorePass) {
        this.serverKeyStorePass = serverKeyStorePass;
    }

    public String getClientKeyStore() {
        return clientKeyStore;
    }

    public void setClientKeyStore(String clientKeyStore) {
        this.clientKeyStore = clientKeyStore;
    }

    public String getClientKeyStorePass() {
        return clientKeyStorePass;
    }

    public void setClientKeyStorePass(String clientKeyStorePass) {
        this.clientKeyStorePass = clientKeyStorePass;
    }

    public String getTrustedClients() {
        return trustedClients;
    }

    public void setTrustedClients(String trustedClients) {
        this.trustedClients = trustedClients;
    }

    public String getTrustedClientsStorePass() {
        return trustedClientsStorePass;
    }

    public void setTrustedClientsStorePass(String trustedClientsStorePass) {
        this.trustedClientsStorePass = trustedClientsStorePass;
    }

    public String getTransferMsg() {
        return transferMsg;
    }

    public void setTransferMsg(String transferMsg) {
        this.transferMsg = transferMsg;
    }

    public boolean isSslLog() {
        return sslLog;
    }

    public void setSslLog(boolean sslLog) {
        this.sslLog = sslLog;
    }
}
