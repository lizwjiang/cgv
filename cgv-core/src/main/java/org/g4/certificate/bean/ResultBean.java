package org.g4.certificate.bean;

import java.io.Serializable;

/**
 * Return all the results
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class ResultBean implements Serializable {
    private boolean success = true;
    private boolean exception;
    private String cause;
    private String errorCode;
    private String errorMessage;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public boolean isException() {
        return exception;
    }

    public void setException(boolean exception) {
        this.exception = exception;
        if(exception){
            success = false;
        }
    }

    public String getCause() {
        return cause;
    }

    public void setCause(String cause) {
        this.cause = cause;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
