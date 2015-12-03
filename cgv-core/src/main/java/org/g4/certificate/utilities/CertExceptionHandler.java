package org.g4.certificate.utilities;

import org.g4.certificate.exception.CGVRuntimeException;
import org.g4.certificate.facade.CertLogger;

/**
 * The handler is the entry to handle any exception
 * User: Johnson Jiang
 * Date: 12/3/15
 * Time: 3:42 PM
 */
public class CertExceptionHandler {
    static CertLogger logger = CertLogger.getLogger(CertExceptionHandler.class.getName());

    public static void handleException(Exception e, String msg) {
        logger.error(msg, e);
        throw new CGVRuntimeException(msg, e);
    }

    public static void handleException(Exception e){
        logger.error(e);
        throw new CGVRuntimeException(e);
    }
}
