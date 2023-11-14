package com.github.piantino.keycloak;

import org.keycloak.Config;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.PasswordCredentialModel;

public class LdapLocalUserCredentialProviderFactory
        implements CredentialProviderFactory<LdapLocalUserCredentialValidator> {

    private Config.Scope config;

    @Override
    public String getId() {
        return "ldap-local-user-credential";
    }

    @Override
    public void init(Config.Scope config) {
        this.config = config;
    }

    @Override
    public CredentialProvider<PasswordCredentialModel> create(KeycloakSession session) {
        return new LdapLocalUserCredentialValidator(session, this.config);
    }

}
