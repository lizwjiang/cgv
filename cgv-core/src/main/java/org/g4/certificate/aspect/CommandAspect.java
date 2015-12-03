package org.g4.certificate.aspect;

/**
 * The interface of command aspect. That indicates if need to do something before/after a command is executed.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public interface CommandAspect {
    public void beforeCommand(Object... o);

    public void afterCommand(Object... o);
}
