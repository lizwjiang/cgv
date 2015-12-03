package org.g4.certificate.exception;

/**
 * Exception thrown when Java Home can not be found from system environment
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class JavaHomeNotFoundException extends CGVRuntimeException{
    public JavaHomeNotFoundException(String message){
        super(message);
    }

    public JavaHomeNotFoundException(String message, Throwable t){
        super(message, t);
    }
}
