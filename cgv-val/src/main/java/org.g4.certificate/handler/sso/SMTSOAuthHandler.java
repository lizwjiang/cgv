package org.g4.certificate.handler.sso;

import org.g4.certificate.auth.ssl.SSLClient;
import org.g4.certificate.auth.ssl.SSLServer;
import org.g4.certificate.bean.CertAuthBean;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.TSOCertAuthParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A helper class to authenticate the certificates of TSO
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class SMTSOAuthHandler {
    CertLogger logger = CertLogger.getLogger(SMTSOAuthHandler.class.getName());
    private static String slash = CertParamTemplate.CERT_SLASH;

    /**
     * Handle the request of authentication on TSO certificates
     *
     * @param ph
     */
    public void handleRequest(TSOCertAuthParamParser ph) {
        String cacerts = ph.getCertAuthRootDir() + CertParamTemplate.CERT_JAVA_KEYSTORE;
        if (!CertUtil.isValidKeystore(cacerts, CertParamTemplate.CERT_CA_CACERTS_PASSWORD)) return;
        CertUtil.setCAKeyStore(cacerts, CertParamTemplate.CERT_CA_CACERTS_PASSWORD);

        List<String> clientKeystoreList = FileUtil.getFileList(ph.getCertAuthRootDir() + slash + CertParamTemplate.CERT_AUTH_CLIENT_PATH);
        List<String> serverKeystoreList = FileUtil.getFileList(ph.getCertAuthRootDir() + slash + CertParamTemplate.CERT_AUTH_SERVER_PATH);

        createServerSocket(serverKeystoreList, clientKeystoreList, ph);
    }

    private void createServerSocket(List<String> serverKeystoreList, List<String> clientKeystoreList, TSOCertAuthParamParser ph) {
        ExecutorService pool = Executors.newCachedThreadPool();

        for (String serverCert : serverKeystoreList) {
            CertAuthBean cab = new CertAuthBean();
            cab.setServerKeyStore(serverCert);
            cab.setServerKeyStorePass(ph.getServerKeystorePass());
            cab.setTrustedClients(ph.getCertAuthRootDir() + CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE);
            cab.setTrustedClientsStorePass(ph.getTrustedClientsPass());
            cab.setClientKeyStorePass(ph.getClientKeystorePass());

            // if the port is being used, server socket will not be created.
            // Here is to monitor the port. if the port is used and is not released in 20 sec,
            // throw error and exit the system.
            if (!monitorSocketPort()) System.exit(0);

            pool.execute(new SSLServer(cab));

            createClientSocket(clientKeystoreList, cab);
        }
        pool.shutdown();
    }

    private boolean monitorSocketPort() {
        Long startTime = System.currentTimeMillis();
        Long timeDiff;
        while (true) {
            if (!CertUtil.isLocalPortUsed(CertParamTemplate.SERVER_SOCKET_PORT))
                break;
            timeDiff = System.currentTimeMillis() - startTime;
            if (timeDiff / 1000 >= 20) {
                logger.printToConsole("Can not reach the port : " + CertParamTemplate.SERVER_SOCKET_PORT + "in " + timeDiff / 1000 + "s");
                return false;
            }
        }
        return true;
    }

    private void createClientSocket(List<String> clientKeystoreList, CertAuthBean cab) {
        int clientCertCount = 0;
        for (String clientCert : clientKeystoreList) {
            cab.setClientKeyStore(clientCert);
            cab.setClientKeyStorePass(cab.getClientKeyStorePass());
            clientCertCount++;

            if (clientCertCount == clientKeystoreList.size()) {
                cab.setTransferMsg(CertParamTemplate.LAST_CERT_IN_ONE_LOOP);
            }
            new SSLClient(cab).handshake();
        }
    }


}
