package org.g4.certificate.handler;

import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * By default, the logging.properties is under /lib/security folder and is loaded if calling java logging.
 * Here to copy the file inside this project and load it by LogManager class.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 * @see LogManager
 */
public class LoggingHandler {
    private static Logger logger = null;

    private LoggingHandler() {
    }

    public static Logger getLogger(String name) {
        InputStream is = FileUtil.getRelativeInputStream(CertParamTemplate.RESOURCES_APP_SETTINGS__PATH + "log/logging.properties");

        try {
            LogManager.getLogManager().readConfiguration(is);
        } catch (Exception e) {
            //do nothing, only output the logs to console
            System.out.println("Exception happens when reading logging.properties");
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                //do nothing, only need to output the logs to console
                System.out.println("Exception happens on closing input steam when reading the log configuration file");
            }
        }
        logger = Logger.getLogger(name);

        return logger;
    }

    public static String getAllParmsInCommandLine(String[] args) {
        StringBuffer sb = new StringBuffer();
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                sb.append(args[i]).append(" ");
            }
        }

        return sb.toString();
    }

}
