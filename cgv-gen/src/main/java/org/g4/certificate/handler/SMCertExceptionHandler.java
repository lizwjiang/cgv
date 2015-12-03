package org.g4.certificate.handler;

import org.g4.certificate.exception.SMRuntimeException;
import org.g4.certificate.facade.CertLogger;

/**
 * Whatever exception is thrown, must call handleException of SMCertExceptionHandler to handle
 *
 * @author : Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class SMCertExceptionHandler {
    static CertLogger logger = CertLogger.getLogger(SMCertExceptionHandler.class.getName());

    public static void handleException(Exception e, String msg) {
        logger.error(msg, e);
        throw new SMRuntimeException(msg, e);
    }

    public static void handleException(Exception e){
        logger.error(e);
        throw new SMRuntimeException(e);
    }
}
