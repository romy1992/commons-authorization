package com.commons.authorization.exception;

public class RoleException extends Exception {

  public RoleException() {
    super();
  }

  public RoleException(String message) {
    super(message);
  }

  public RoleException(String message, Throwable cause) {
    super(message, cause);
  }

  public RoleException(Throwable cause) {
    super(cause);
  }

  protected RoleException(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
