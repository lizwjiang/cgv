package org.g4.certificate.exception;

/**
 * Exception
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CGVRuntimeException extends RuntimeException{
    public CGVRuntimeException(String message) {
        super(message);
    }

    public CGVRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public CGVRuntimeException(Throwable cause) {
        super(cause);
    }
}
