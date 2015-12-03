package org.g4.certificate.parser;

import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;

import java.util.List;

/**
 * Handler that is used to handle input parameters in command line when validating the certificates of TSO
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class TSOCertAuthParamParser extends CertAuthParamParser {
    private CertLogger logger = CertLogger.getLogger(TSOCertAuthParamParser.class.getName());

    //below parameters used for TSO certificate validation
    private final String directoryParam = "-d";
    private final String clientKeystorePassParam = "-client_keystorePass";
    private final String serverKeystorePassParam = "-server_keystorePass";
    private final String trustedClientsPassParam = "-ssl_trustedClientsPwd";

    private String certAuthRootDir = FileUtil.getJarCurrentPath() + CertParamTemplate.CERT_AUTH_ROOT_PATH + CertParamTemplate.CERT_SLASH;
    private String clientKeystorePass = CertParamTemplate.CERT_CLIENT_KEYSTORE_PASSWORD;
    private String serverKeystorePass = CertParamTemplate.CERT_SERVER_KEYSTORE_PASSWORD;
    private String trustedClientsPass = CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE_PASSWORD;

    /**
     * The command line should be like CertAuth -<different parameters>
     * apache/tso/f5            indentify which type of certificates needs to be validated
     * d                        the root path of certificates to be validated
     * client_keystorePass      password of client key store
     * server_keystorePass      password of server key store
     * ssl_trustedClientsPwd    password of key store of trusted client
     * <p/>
     * The rules for validation:
     * Rule 1 : one of apache, tso and F5 should be specified
     * Rule 2 : there should not be invalid parameters
     * Rule 3 : check if a parameter needs to be followed the value e.g. -d -client_keystorePass
     * Rule 4 : validate if a valid directory is following if "-d" is specified.
     * Rule 5 : check if duplicated parameters are specified
     * Rule 6 : no matter whether the structure of certificate directory should not be broken
     *
     * @param args
     * @return
     */
    public boolean analyzeParams(String[] args) {
        int dirCount = 0;
        boolean isPass;

        String[] paramArray = new String[]{
                directoryParam,
                clientKeystorePassParam,
                serverKeystorePassParam,
                trustedClientsPassParam
        };

        if (!super.analyzeParams(args, paramArray)) return false;

        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equalsIgnoreCase(directoryParam)) {
                    dirCount++;
                    isPass = validateParam(i, args, paramArray);
                    if (!isPass) {
                        return false;
                    } else {
                        if (!FileUtil.isDir(args[i + 1])) {
                            logger.printToConsole("The certificate path specified by -d is invalid");
                            return false;
                        } else {
                            this.certAuthRootDir = args[i + 1].replace(CertParamTemplate.CERT_DOUBLE_QUOTATION, "").trim();
                            if(!certAuthRootDir.endsWith(CertParamTemplate.CERT_SLASH)) {
                                certAuthRootDir += CertParamTemplate.CERT_SLASH;
                            }
                            //need to validate the folder structure. e.g. there should be two folders named Servers and Clients which can not be changed
                            //and two files named cacerts and trustedclients.keystore, but the names of the two files can be changed.
                            if (!isValidCertPath4Auth(certAuthRootDir))
                                return false;
                        }

                        if (i + 1 <= args.length - 1) {
                            i++;
                        }

                    }
                } else if (args[i].equalsIgnoreCase(clientKeystorePassParam)) {
                    //clientkeystorePass
                    isPass = validateParam(i, args, paramArray);
                    if (!isPass) {
                        return false;
                    } else {
                        this.clientKeystorePass = args[i + 1];
                        if (i + 1 <= args.length - 1) {
                            i++;
                        }
                    }

                } else if (args[i].equalsIgnoreCase(serverKeystorePassParam)) {
                    //serverkeystorePass
                    isPass = validateParam(i, args, paramArray);
                    if (!isPass) {
                        return false;
                    } else {
                        this.serverKeystorePass = args[i + 1];
                        if (i + 1 <= args.length - 1) {
                            i++;
                        }
                    }

                } else if (args[i].equalsIgnoreCase(trustedClientsPassParam)) {
                    //trustedClientsPass
                    isPass = validateParam(i, args, paramArray);
                    if (!isPass) {
                        return false;
                    } else {
                        this.trustedClientsPass = args[i + 1];
                        if (i + 1 <= args.length - 1) {
                            i++;
                        }
                    }
                }
            }

            if (dirCount == 0) {
                //use the default certificate root path - CMT_AUTH_CERTS
                String tsoAuthPath = FileUtil.getJarCurrentPath() +
                        CertParamTemplate.CERT_AUTH_ROOT_PATH +
                        CertParamTemplate.CERT_SLASH +
                        CertParamTemplate.CERT_TRUSTEDSIGNON_FOLDER +
                        CertParamTemplate.CERT_SLASH ;
                this.certAuthRootDir = tsoAuthPath;
                if (!isValidCertPath4Auth(tsoAuthPath))
                    return false;
            }
        }

        return true;
    }

    /**
     * Rule 1 ：There should be two folders named Servers and clients under root folder
     * Rule 2 : There at least should be two files named cacerts and trustedclients.keystore
     * Rule 3 : there should be files in Servers and Clients folders.
     *
     * @param rootPath
     * @return
     */
    private boolean isValidCertPath4Auth(String rootPath) {

        //start validate rule 1
        List<String> fileNameList = FileUtil.getFileNameList(rootPath);
        int fileCount = 0;
        for (String fileName : fileNameList) {
            if (fileName.equals(CertParamTemplate.CERT_JAVA_KEYSTORE)) {
                fileCount++;
            } else if (fileName.equals(CertParamTemplate.CERT_TRUST_CLIENTS_KEYSTORE)) {
                fileCount++;
            }
        }
        if (fileNameList.isEmpty() || fileCount != 2) {
            logger.printToConsole("Can not find cacerts and trustedclients.keystore under " + rootPath);
            return false;
        }

        //start validate rule 2
        List<String> dirNameList = FileUtil.getDirNameList(rootPath);
        int dirCount = 0;
        for (String dirName : dirNameList) {
            if (dirName.equals(CertParamTemplate.CERT_AUTH_SERVER_PATH)) {
                dirCount++;
            } else if (dirName.equals(CertParamTemplate.CERT_AUTH_CLIENT_PATH)) {
                dirCount++;
            }
        }
        if (dirCount != 2) {
            logger.printToConsole("Can not find folders named Servers and Clients under " + rootPath);
            return false;
        }

        //start rule 3
        String serverKeystorePath = rootPath + CertParamTemplate.CERT_AUTH_SERVER_PATH;
        List<String> serverList = FileUtil.getFileNameList(serverKeystorePath);
        if (serverList.isEmpty()) {
            logger.printToConsole("There are no server keystore files under " + serverKeystorePath);
            return false;
        }

        String clientKeystorePath = rootPath + CertParamTemplate.CERT_AUTH_CLIENT_PATH;
        List<String> clientList = FileUtil.getFileNameList(clientKeystorePath);
        if (clientList.isEmpty()) {
            logger.printToConsole("There are no client keystore files under " + clientKeystorePath);
            return false;
        }

        return true;
    }

    public String getTrustedClientsPass() {
        return trustedClientsPass;
    }

    public String getServerKeystorePass() {
        return serverKeystorePass;
    }

    public String getClientKeystorePass() {
        return clientKeystorePass;
    }

    public String getCertAuthRootDir() {
        return certAuthRootDir;

    }

}
