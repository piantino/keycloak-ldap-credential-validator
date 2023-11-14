package com.github.piantino.keycloak;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import javax.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

import dasniko.testcontainers.keycloak.KeycloakContainer;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
public class LdapCredentialValidatorTest {

        private Network network = Network.newNetwork();

        private KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:18.0.2")
                        .withAdminUsername("admin")
                        .withAdminPassword("tops3cr3t")
                        .withProviderClassesFrom("target/classes")
                        .withEnv("DEBUG_MODE", "true")
                        .withEnv("DEBUG_PORT", "8000")
                        .withEnv("JAVA_OPTS", "-agentlib:jdwp=transport=dt_socket,server=y,address=*:8000,suspend=n")
                        .withExposedPorts(8080, 8000)
                        .withNetwork(network)
                        .withRealmImportFile("realm-export.json")
                        .withCopyFileToContainer(MountableFile.forClasspathResource("keycloak.conf"),
                                        "/opt/keycloak/conf/keycloak.conf")
                        .withEnv("TZ", "America/Sao_Paulo");

        private GenericContainer<?> ldap = new GenericContainer<>("rroemhild/test-openldap:2.1")
                        .withExposedPorts(10389)
                        .withNetwork(network)
                        .withNetworkAliases("openldap");

        private Keycloak client;
        private RealmResource realm;
        private AuthzClient authzClient;

        @BeforeAll
        public void init() throws JsonParseException, JsonMappingException, IOException {

                Stream.of(keycloak, ldap).parallel().forEach(GenericContainer::start);

                client = KeycloakBuilder.builder()
                                .serverUrl(keycloak.getAuthServerUrl())
                                .realm("master")
                                .clientId("admin-cli")
                                .username(keycloak.getAdminUsername())
                                .password(keycloak.getAdminPassword())
                                .build();

                realm = client.realm("test-realm");

                Map<String, Object> credentials = new HashMap<String, Object>();
                credentials.put("secret", "SoBy2IbD8fYPPP2iM6sNNqVcrkl57Qie");
                Configuration configuration = new Configuration(keycloak.getAuthServerUrl(), "test-realm", "my-app",
                                credentials, null);

                authzClient = AuthzClient.create(configuration);
        }

        @Test
        @Order(1)
        public void createAppClient() {
                ClientRepresentation clientRepresentation = new ClientRepresentation();
                clientRepresentation.setId("my-app");
                clientRepresentation.setName("My App Client");
                clientRepresentation.setSecret("SoBy2IbD8fYPPP2iM6sNNqVcrkl57Qie");
                clientRepresentation.setDirectAccessGrantsEnabled(true);

                Response response = realm.clients().create(clientRepresentation);
                assertEquals(201, response.getStatus(), "Status HTTP created");
        }

        @Test
        @Order(2)
        public void createLocalUsers() {
                createUser("fry");
                createUser("bender");
        }

        @Test
        @Order(3)
        public void validatePasswordInLdap() {
                try {
                        AccessTokenResponse response = authzClient.obtainAccessToken("fry", "fry");
                        assertNotNull(response.getToken(), "ID Token");
                        // TODO: Check ldap attributes
                } catch (HttpResponseException e) {
                        assertEquals("Invalid user credentials", e.getReasonPhrase());
                        fail("Invalid credential", e);
                }
        }

        @Test
        @Order(4)
        public void invalidPasswordInLdap() {
                try {
                        authzClient.obtainAccessToken("bender", "Destruct1A2B3");
                        fail("Credential must be invalid");
                } catch (HttpResponseException e) {
                        assertEquals("Unauthorized", e.getReasonPhrase(), "Must be invalid");
                }

        }

        private void createUser(String username) {
                UserRepresentation user = new UserRepresentation();
                user.setUsername(username);
                user.setEnabled(true);

                Response response = realm.users().create(user);
                assertEquals(201, response.getStatus(), "Status HTTP created");
        }
}
