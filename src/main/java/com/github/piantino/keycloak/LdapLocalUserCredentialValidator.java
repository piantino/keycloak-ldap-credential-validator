package com.github.piantino.keycloak;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

import com.github.piantino.keycloak.config.LdapConfig;
import com.github.piantino.keycloak.exception.LdapLocalUserCredentialException;

public class LdapLocalUserCredentialValidator
        implements CredentialProvider<PasswordCredentialModel>, CredentialInputValidator {

    protected static final Logger LOGGER = Logger.getLogger(LdapLocalUserCredentialValidator.class);

    private Config.Scope config;

    public LdapLocalUserCredentialValidator(KeycloakSession session, Config.Scope config) {
        this.config = config;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return new LdapConfig(this.config, realm).isConfigured();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {

        if (!isConfiguredFor(realm, user, getType())) {
            return false;
        }

        LOGGER.debugv("Validating password in LDAP for {0}", user.getUsername());

        if (user.getFirstAttribute(LDAPConstants.LDAP_ENTRY_DN) == null) {
            String distinguishedName = searchUserLdapEntryDn(realm, user);

            if (distinguishedName == null) {
                return false;
            }
            user.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, distinguishedName);
        }

        try {
            createLdapContext(realm, user.getFirstAttribute(LDAPConstants.LDAP_ENTRY_DN),
                    credentialInput.getChallengeResponse());
        } catch (NamingException e) {
            LOGGER.debugv(e, "Ldap auth error for " + user.getUsername());
            return false;
        }

        return true;
    }

    @Override
    public String getType() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public PasswordCredentialModel createCredential(RealmModel realm, UserModel user,
            PasswordCredentialModel credentialModel) {
        throw new UnsupportedOperationException("Not use the method 'createCredential'");
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        throw new UnsupportedOperationException("Not use the method 'deleteCredential'");
    }

    @Override
    public PasswordCredentialModel getCredentialFromModel(CredentialModel model) {
        throw new UnsupportedOperationException("Not use the method 'getCredentialFromModel'");
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        throw new UnsupportedOperationException("Not use the method 'getCredentialTypeMetadata'");
    }

    private InitialDirContext createLdapContext(RealmModel realm, String distinguishedName, String password)
            throws NamingException {
        LdapConfig ldapConfig = new LdapConfig(this.config, realm);

        Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, ldapConfig.getContextFactory());
        environment.put(Context.PROVIDER_URL, ldapConfig.getConectionUrl());
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, distinguishedName);
        environment.put(Context.SECURITY_CREDENTIALS, password);

        return new InitialDirContext(environment);
    }

    private String searchUserLdapEntryDn(RealmModel realm, UserModel user) {
        LdapConfig ldapConfig = new LdapConfig(this.config, realm);

        String distinguishedName = ldapConfig.getBindDn();
        String password = ldapConfig.getBindCredential();

        try {
            String filter = getUserFilter(user, ldapConfig);
            String[] returningAttrs = { "cn" };

            InitialDirContext context = createLdapContext(realm, distinguishedName, password);

            SearchControls searchControls = new SearchControls();
            searchControls.setReturningAttributes(returningAttrs);
            searchControls.setSearchScope(ldapConfig.getSearchScope());
            NamingEnumeration<SearchResult> searchResults = context.search(
                    ldapConfig.getUsersDn(),
                    filter,
                    searchControls);

            if (searchResults.hasMore()) {

                SearchResult result = (SearchResult) searchResults.next();
                Attributes attrs = result.getAttributes();

                LOGGER.debugv("DN {0} - {1}", result.getNameInNamespace(), attrs);
                return result.getNameInNamespace();
            }

        } catch (NamingException e) {
            throw new LdapLocalUserCredentialException("Error on search DN for user " + user.getUsername(), e);
        }
        return null;
    }

    private String getUserFilter(UserModel user, LdapConfig ldapConfig) {
        List<String> filters = new ArrayList<>();

        filters.add(String.format("%s=%s", ldapConfig.getUsernameLdapAttribute(), user.getUsername()));

        String[] ObjectClasses = ldapConfig.getUsernameObjectClasses().split(",");
        
        for (String objectClass : ObjectClasses) {
            filters.add(String.format("objectClass=%s", objectClass));
        }
        return "(&(" + String.join(")(", filters) + "))";
    }
}
