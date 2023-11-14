package com.github.piantino.keycloak.exception;

public class LdapLocalUserCredentialException extends RuntimeException {


    public LdapLocalUserCredentialException(String message) {
        super(message);
    }

    public LdapLocalUserCredentialException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
