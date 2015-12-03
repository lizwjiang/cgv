package org.g4.certificate.facade;

import org.g4.certificate.exception.CGVRuntimeException;
import org.g4.certificate.handler.LoggingHandler;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.FileUtil;
import org.g4.certificate.utilities.PropertiesAnalyzer;

import java.io.InputStream;
import java.util.logging.Level;


/**
 * Consider Java logging and log4j are used in different scenarios,
 * this is designed to a facade which provides two types of logging
 *
 * @author Johnson Jiang
 * @since 1.0
 * @version 1.0
 */
public class CertLogger {
    // ENV : from environment JRE, SM: from SM JRE
    private static String logType;
    private static org.apache.log4j.Logger log4j_logger;
    private static java.util.logging.Logger java_logger;
    private static boolean canOutputConsole = true;

    private static boolean isDebug = false;

    private final static ThreadLocal loggerLocal = new ThreadLocal();

    private CertLogger() {
    }

    public static CertLogger getLogger(String name) {
        CertLogger logger = (CertLogger) loggerLocal.get();
        if (logger == null) {
            logger = new CertLogger();
            loggerLocal.set(logger);
        }

        if (CertUtil.isNull(logger.logType)) logType = getLogType();

        if (logType.equalsIgnoreCase("javaLogging")) {
            java_logger = LoggingHandler.getLogger(name);
        } else {
            //In SM RTE, the log4j is only used for java part and has below features:
            //1. need to specify the parameter in sm.ini - log4jDebug:com.hp,org.jgroups
            //2. only debug level is available, no others.
            //3. all logs are outputted in sm.log starting with JRTE key word
            //if using log4j of SM RTE, need to find sm.ini first and then set the log level to debug.
            log4j_logger = org.apache.log4j.Logger.getLogger(name);
        }
        return logger;
    }

    public void debug(String msg) {
        if (logType.equalsIgnoreCase("javaLogging")) {
            java_logger.info(msg);
        } else {
            log4j_logger.debug(msg);
        }
    }

    public void error(String msg, Throwable t) {
        if (logType.equalsIgnoreCase("javaLogging")) {
            java_logger.log(Level.SEVERE, msg, t);
        } else {
            log4j_logger.error(msg, t);
        }
    }

    public void error(Throwable t) {
        if (logType.equalsIgnoreCase("javaLogging")) {
            java_logger.log(Level.SEVERE, null, t);
        } else {
            log4j_logger.error(t);
        }
    }

    private static String getLogType() {
        InputStream is;

        try {
            is = FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_APP_SETTINGS__PATH + "app_setting.properties");
            logType = PropertiesAnalyzer.getProperties(is).getProperty("log.type");
        } catch (Exception e) {
            throw new CGVRuntimeException("Errors happens when getting what is used to print log between log4j and java logging",e);
        }
        return logType;
    }

    public void printToConsole(String msg){
        if(canOutputConsole)
            System.out.println(msg);
    }

    public void printToConsoleAndLogFile(String msg, Throwable t){
        if(canOutputConsole)
            System.out.println(msg);
        error(msg, t);
    }
}
