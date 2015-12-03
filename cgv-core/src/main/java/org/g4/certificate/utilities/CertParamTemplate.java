package org.g4.certificate.utilities;

import java.io.File;

/**
 * All constant variables are defined in here
 *
 * @author Johnson Jiang
 * @since 1.0
 */
public class CertParamTemplate {
    public final static int CERT_COMMAND_TYPE_KEYTOOL = 0;
    public final static int CERT_COMMAND_TYPE_OPENSSL = 1;

    public final static String CERT_KEYTOOL_COMMAND = "keytool";

    public final static String CERT_ROOT_FOLDER = "CMT_GEN_CERTS";
    public final static String CERT_TRUSTEDSIGNON_FOLDER = "TrustedSignOn";
    public final static String CERT_APACHE_FOLDER = "Apache";
    public final static String CERT_F5_FOLDER = "SM_F5";
    public final static String CERT_CLIENTS_FOLDER = "Clients";
    public final static String CERT_SERVERS_FOLDER = "Servers";
    public final static String CERT_CLIENT_FOLDER = "client";
    public final static String CERT_SERVER_FOLDER = "server";
    public final static String CERT_LB_FOLDER = "LB";
    public final static String CERT_LB_CLIENT_PROFILE = "Client_SSL_Profile";
    public final static String CERT_LB_SERVER_PROFILE = "Server_SSL_Profile";
    public final static String CERT_TEMP_FOLDER = "TEMP";
    public final static String CERT_CA_FOLDER = "CA";
    public final static String CERT_TRUSTEDCLIENTS_FLODER = "TrustedClients";
    public final static String CERT_SLASH = File.separator;
    public final static String CERT_COMMA = ",";
    public final static String CERT_DOUBLE_QUOTATION = "\"";
    public final static String CERT_PARAMETER_PREFIX = "-";
    public final static String CERT_SOCKET_SEP = "@@##";

    //common properties in property file
    public final static String PARAMETER_CA_COMMON_NAME = "ca.common.name";
    public final static String PARAMETER_CA_ROOT_PASS = "caroot.passowrd";
    public final static String PARAMETER_CA_TRUSTSTORE_PASS = "ca.truststorePass";
    public final static String PARAMETER_SERVER_LIST = "server.list";
    public final static String PARAMETER_CLIENT_LIST = "client.list";
    public final static String PARAMETER_SUFFIX_FQDN = "fqdn";
    public final static String PARAMETER_DNAME_TYPE = "dname.type";
    public final static String PARAMETER_PREFIX_GLOBAL = "global";
    public final static String PARAMETER_PREFIX_SERVER = "server";
    public final static String PARAMETER_PREFIX_CLIENT = "client";
    public final static String PARAMETER_PREFIX_CLIENT_SERVER = "client_server";
    public final static String PARAMETER_PREFIX_CA = "ca";
    public final static String PARAMETER_DNAME_OU = "ou";
    public final static String PARAMETER_DNAME_O = "o";
    public final static String PARAMETER_DNAME_L = "l";
    public final static String PARAMETER_DNAME_ST = "st";
    public final static String PARAMETER_DNAME_C = "c";
    public final static String PARAMETER_DNAME_EMAIL = "email";
    public final static String PARAMETER_SERVER_KEYSTORE_PASS = "server.keystorePass";
    public final static String PARAMETER_SERVER_TRUSTEDCLIENTS_PWD = "server.trustedClientsPwd";
    public final static String PARAMETER_CLIENT_KEYSTORE_PASS = "client.keystorePass";
    public final static String PARAMETER_SERVER_FQDN = "server.fqdn";

    //TSO properties in property file
    public final static String SM_TSO_CERT_PROPS_FILE = "SM_TSO_CERT_PROPS.conf";
    public final static String SM_TSO_CERT_PROPS_FILE_TEMPLATE = "SM_TSO_CERT_PROPS.conf.template";
    public final static int PARAMETER_DNAME_TYPE_GLOBAL = 0;
    public final static int PARAMETER_DNAME_TYPE_CLIENT_SERVER = 1;
    public final static int PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP = 2;
    public final static int PARAMETER_DNAME_TYPE_CA = 5;
    public final static String PARAMETER_LOADBALANCER = "loadbalancer";

    //F5 properties in property file
    public final static String SM_F5_CERT_PROPS_FILE = "SM_F5_CERT_PROPS.conf";
    public final static String SM_F5_CERT_PROPS_FILE_TEMPLATE = "SM_F5_CERT_PROPS.conf.template";
    public final static String PARAMETER_PREFIX_F5 = "f5";
    public final static String PARAMETER_F5_LIST = "f5.list";
    public final static String PARAMETER_PREFIX_CLIENT_F5_SERVER = "client_f5_server";
    public final static int PARAMETER_F5_DNAME_TYPE_GLOBAL = 0;
    public final static int PARAMETER_F5_DNAME_TYPE_CLIENT_F5_SERVER = 1;
    public final static int PARAMETER_F5_DNAME_TYPE_CLIENT_SERVER = 2;
    public final static int PARAMETER_F5_DNAME_TYPE_SEP = 3;
    public final static int PARAMETER_F5_DNAME_TYPE_CA = 5;
    public final static String PARAMETER_F5_COMMON_NAME = "f5.common.name";
    public final static String PARAMETER_SERVER_COMMON_NAME = "server.common.name";
    public final static String PARAMETER_F5_SERVER_KEYSTOREPASS = "f5.server.keystorePass";
    public final static String PARAMETER_F5_CLIENT_KEYSTOREPASS = "f5.client.keystorePass";

    //Apache properties in property file
    public final static String SM_APACHE_CERT_PROPS_FILE = "SM_APACHE_CERT_PROPS.conf";
    public final static String SM_APACHE_CERT_PROPS_FILE_TEMPLATE = "SM_APACHE_CERT_PROPS.conf.template";
    public final static int PARAMETER_APACHE_DNAME_TYPE_GLOBAL = 0;
    public final static int PARAMETER_APACHE_DNAME_TYPE_CLIENT_SERVER = 1;
    public final static String PARAMETER_CLIENT_COMMON_NAME = "client.common.name";

    // Used in type field of CertPropsBean
    public final static int CERT_GEN_TYPE_LB = 0;
    public final static int CERT_GEN_TYPE_SERVER = 1;
    public final static int CERT_GEN_TYPE_CLIENT = 2;
    public final static int CERT_GEN_TYPE_CA = 3;

    public final static String KEY_STORE_EXTENSION = ".keystore";

    //below is the default values which are used to generate TSO certificated
    public final static String CERT_CA_KEY = "cakey.pem";
    public final static String CERT_CA_KEY_PASSWORD = "caroot";
    public final static String CERT_CA_ROOT_CERT = "mycacert.pem";
    public final static String CERT_CA_CACERTS_PASSWORD = "changeit";

    public final static String CERT_JAVA_KEYSTORE = "cacerts";
    public final static String CERT_JAVA_KEYSTORE_BACKUP = "cacerts.orig";
    public final static String CERT_CA_ROOT_CERT_IMPORT_ALIAS = "servicemanager";
    public final static String CERT_CA_ROOT_CERT_IMPORT_ALIAS_HWLB = "hwlbca";

    public final static String CERT_SERVER_KEY_ALIAS = "smserver";
    public final static String CERT_SERVER_KEYSTORE = "server.keystore";
    public final static String CERT_SERVER_KEYSTORE_PASSWORD = "serverkeystore";
    public final static String CERT_SERVER_KEY_PASSWORD = "serverkeystore";
    public final static String CERT_SERVER_REQUEST_CERTIFICATE = "servercert_request.crs";
    public final static String CERT_SERVER_CERTIFICATE = "smservercert.pem";

    public final static String CERT_F5_KEY_ALIAS = "hwlb";
    public final static String CERT_F5_KEYSTORE = "hwlb.keystore";
    public final static String CERT_F5_EXPORT_KEY = "exported.key";
    public final static String CERT_F5_EXPORT_KEY_RSA = "exported_rsa.key";
    public final static String CERT_F5_CERTIFICATE = "hwlbcert.pem";

    public final static String CERT_CLIENT_KEYSTORE_PASSWORD = "clientkeystore";
    public final static String CERT_CLIENT_KEY_PASSWORD = "clientkeystore";
    public final static String CERT_CLIENT_REQUEST_CERTIFICATE = "clientcert_request.crs";
    public final static String CERT_CLIENT_CERTIFICATE = "scclientcert.pem";

    public final static String CERT_CLIENT_PUBLIC_KEY = "clientpubkey.cert";
    public final static String CERT_TRUST_CLIENTS_KEYSTORE = "trustedclients.keystore";
    public final static String CERT_TRUST_CLIENTS_KEYSTORE_PASSWORD = "trustedclients";

    public final static String CERT_CA_KEY_APACHE = "ca.key";
    public final static String CERT_CA_CERT_APACHE = "ca.crt";
    public final static String CERT_SERVER_KEY_APACHE = "server.key";
    public final static String CERT_SERVER_CSR_APACHE = "server.csr";
    public final static String CERT_SERVER_CRT_APACHE = "server.crt";
    public final static String CERT_CLIENT_KEY_APACHE = "client.key";
    public final static String CERT_CLIENT_CSR_APACHE = "client.csr";
    public final static String CERT_CLIENT_CRT_APACHE = "client.crt";
    public final static String CERT_CLIENT_P12_APACHE = "client.p12";


    public final static String RESOURCES_OPENSSL_PATH = "/com/hp/servicemanager/certificate/resources/openssl/";
    public final static String RESOURCES_APP_SETTINGS__PATH = "/com/hp/servicemanager/certificate/resources/";
    public final static String RESOURCES_TEMPLATE_PATH = "/com/hp/servicemanager/certificate/resources/template/";

    public final static String SYSTEM_ENV_JAVA_HOME = "JAVA_HOME";

    public final static String JRE_CACERTS_PATH = "lib/security";
    public final static String JRE_BIN_PATH = "bin";

    public final static String SM_TSO_INI = "sm_tso.ini";
    public final static String SM_TSO_WEB_DOT_XML = "web.xml";
    public final static String SM_F5_SSL_SERVER = "SSL_Server.conf";
    public final static String SM_F5_SSL_CLIENT = "SSL_Client.conf";

    public final static String SM_F5_CONF_CERTFICATE = "Certificate";
    public final static String SM_F5_CONF_KEY = "Key";
    public final static String SM_F5_CONF_PASS_PHASE = "Pass Phrase";
    public final static String SM_F5_CONF_TRUSTED_CA = "Trusted Certificate Authorities";

    public final static String SM_INI_SSLCONNECTOR = "sslConnector";
    public final static String SM_INI_SSL = "ssl";
    public final static String SM_INI_SSL_REQCLIENTAUTH = "ssl_reqClientAuth";
    public final static String SM_INI_KEYSTOREFILE = "keystoreFile";
    public final static String SM_INI_KEYSTOREPASS = "keystorePass";
    public final static String SM_INI_SSL_TRUSTEDCLIENTSJKS = "ssl_trustedClientsJKS";
    public final static String SM_INI_SSL_TRUSTEDCLIENTSPWD = "ssl_trustedClientsPwd";
    public final static String SM_INI_TRUSTOREFILE = "truststoreFile";
    public final static String SM_INI_TRUSTOREPASS = "truststorePass";
    public final static String SM_INI_TRUSTEDSIGNON = "trustedSignOn";
    public final static String SM_INI_TYPE_TSO = "tso";
    public final static String SM_INI_TYPE_F5 = "f5";

    public final static String WEB_XML_WEBAPP = "web-app";
    public final static String WEB_XML_VERSION = "version";
    public final static String WEB_XML_INITPARAM = "init-param";
    public final static String WEB_XML_PARAMNAE = "param-name";
    public final static String WEB_XML_PARAMVALUE = "param-value";

    public final static String MAP_KEY_4_CA_CACERTBEAN = "caBean";
    public final static String MAP_KEY_4_CAROOTPASS = "catrootpass";
    public final static String MAP_KEY_4_CATRUSTSTOREPASS = "catruststorepass";
    public final static String MAP_KEY_4_SERVERCOMMONNAME = "servercommonname";
    public final static String MAP_KEY_4_SERVER_CERTBEAN = "servercommonname";
    public final static String MAP_KEY_4_SERVERKEYSTOREPASS = "serverkeystorepass";
    public final static String MAP_KEY_4_SERVERTRUSTEDCLIENTSPASS = "servertrustedclientspass";
    public final static String MAP_KEY_4_CLIENTKEYSTOREPASS = "clientkeystorepass";
    public final static String MAP_KEY_4_CERTPARAMLIST = "certparamlist";
    public final static String MAP_KEY_4_F5_CERTBEAN = "f5Bean";
    public final static String MAP_KEY_4_F5SERVERKEYSTOREPASS = "f5serverkeystorepass";
    public final static String MAP_KEY_4_F5CLIENTKEYSTOREPASS = "f5clientkeystorepass";
    public final static String MAP_KEY_4_CLIENT_CERTBEAN = "clientcommonname";

    public final static String KEY_ENTER = "\r\n";

    public final static String CERT_AUTH_ROOT_PATH = "CMT_VAL_CERTS";
    public final static String CERT_AUTH_SERVER_PATH = "Servers";
    public final static String CERT_AUTH_CLIENT_PATH = "Clients";
    public final static String SOCKET_HELLO_SERVER = "Hello Server";
    public final static String LAST_CERT_IN_ONE_LOOP = "I_am_the_last_one";
    public final static int SOCKET_TIME_OUT = 20 * 1000;
    public final static int SERVER_SOCKET_PORT = 4433;
    public final static String CERT_CAC_FOLDER = "CommonAccessCard";

    public static final String[] CAUSE_METHOD_NAMES = {
            "getCause",
            "getNextException",
            "getTargetException",
            "getException",
            "getSourceException",
            "getRootCause",
            "getCausedByException",
            "getNested",
            "getLinkedException",
            "getNestedException",
            "getLinkedCause",
            "getThrowable",
    };
    public static final String[] PROXY_PROTOCOL = {"http", "https", "ldap"};

    public static final String SYSTEM_PROMPT_START_HANDLING_MSG = "Your request is being handled, please wait......";
}
