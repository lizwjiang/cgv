package org.g4.certificate.exception;

/**
 * Exception thrown when executing command to generate certificate
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CommandExecutionException extends RuntimeException {
    public CommandExecutionException() {
        super();
    }

    public CommandExecutionException(String message) {
        super(message);
    }

    public CommandExecutionException(String message, Throwable cause) {
        super(message, cause);
    }

    public CommandExecutionException(Throwable cause) {
        super(cause);
    }
}
