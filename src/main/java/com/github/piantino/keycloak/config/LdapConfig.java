package com.github.piantino.keycloak.config;

import javax.naming.directory.SearchControls;

import org.keycloak.Config;
import org.keycloak.Config.Scope;
import org.keycloak.models.RealmModel;

import com.github.piantino.keycloak.exception.LdapLocalUserCredentialException;

public class LdapConfig {

    private static final String CONTEXT_FACTORY = "context-factory";
    private static final String CONNECTION_URL = "connection-url";
    private static final String USERS_DN = "users-dn";
    private static final String CUSTOM_USER_LDAP_FILTER = "custom-user-ldap-filter";
    private static final String SEARCH_SCOPE = "search-scope";
    private static final String BIND_DN = "bind-dn";
    private static final String BIND_CREDENTIAL = "bind-credential";
    private static final String USERNAME_LDAP_ATTRIBUTE = "username-ldap-attribute";
    private static final String USERNAME_OBJECT_CLASSES = "username-object-classes";

    private Scope config;

    public LdapConfig(Config.Scope config, RealmModel realm) {
        this.config = config.scope(realm.getName());
    }

    public boolean isConfigured() {
        return this.config.get(CONNECTION_URL) != null;
    }
    
    public String getContextFactory() {
        return this.config.get(CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    }

    public String getConectionUrl() {
        return this.config.get(CONNECTION_URL);
    }

    public String getUsersDn() {
        return this.config.get(USERS_DN);
    }

    public String getCustomUserLdapfilter() {
        return this.config.get(CUSTOM_USER_LDAP_FILTER);
    }

    public int getSearchScope() {
        String searchScope = this.config.get(SEARCH_SCOPE, "SUBTREE");

        if ("SUBTREE".equals(searchScope)) {
            return SearchControls.SUBTREE_SCOPE;
        }

        if ("ONELEVEL".equals(searchScope)) {
            return SearchControls.ONELEVEL_SCOPE;
        }
        throw new LdapLocalUserCredentialException("Invalid value for " + SEARCH_SCOPE + ": " + searchScope);
    }

    public String getBindDn() {
        return this.config.get(BIND_DN);
    }

    public String getBindCredential() {
        return this.config.get(BIND_CREDENTIAL);
    }

    public String getUsernameLdapAttribute() {
        return this.config.get(USERNAME_LDAP_ATTRIBUTE);
    }

    public String getUsernameObjectClasses() {
        return this.config.get(USERNAME_OBJECT_CLASSES);
    }

}
