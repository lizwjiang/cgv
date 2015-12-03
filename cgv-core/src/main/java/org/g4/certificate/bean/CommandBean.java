package org.g4.certificate.bean;

import org.g4.certificate.aspect.CommandAspect;

import java.io.Serializable;

/**
 * When using keytool or OpenSSL to execute some commands to generate certificates,
 * the command with some parameters should be there. This is used to encapsulate all the required data.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CommandBean implements Serializable {
    private String[] command;
    //Something may be need to be done before/after the command is executed.
    //For example, the Java key store named cacerts should replace the original one after being imported the self-signed CA certificate.
    //otherwise, the error will occur when importing any server certificate into key store file.
    private CommandAspect commandAspect = null;
    private Object[] objects = null;

    private String message;

    public CommandBean(String[] command) {
        this.command = command;
    }

    public CommandBean(String[] command, CommandAspect commandAspect, Object[] objects, String message) {
        this.command = command;
        this.commandAspect = commandAspect;
        this.objects = objects;
        this.message = message;
    }

    public void setCommand(String[] command) {
        this.command = command;
    }

    public String[] getCommand() {
        return command;
    }

    public void setCommandAspect(CommandAspect ca) {
        this.commandAspect = ca;
    }

    public CommandAspect getCommandAspect() {
        return commandAspect;
    }

    public void setParams4CommandAspect(Object[] objects) {
        this.objects = objects;
    }

    public Object[] getParams4CommandAspect() {
        return objects;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

}