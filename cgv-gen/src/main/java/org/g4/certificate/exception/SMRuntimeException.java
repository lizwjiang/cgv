package org.g4.certificate.exception;

/**
 * SM runtime exception. parent class of all the exceptions defined in CGA
 *
 * @author Johnson_Jiang
 * @version 1.0
 * @since 1.0
 */
public class SMRuntimeException extends RuntimeException {
    public SMRuntimeException() {
        super();
    }

    public SMRuntimeException(String message) {
        super(message);
    }

    public SMRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public SMRuntimeException(Throwable cause) {
        super(cause);
    }
}
