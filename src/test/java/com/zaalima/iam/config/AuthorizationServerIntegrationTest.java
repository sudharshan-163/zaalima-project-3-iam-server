package com.zaalima.iam.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthorizationServerIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void authorizationServerMetadata_shouldExposeExpectedEndpoints() throws Exception {
        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/.well-known/oauth-authorization-server",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        JsonNode metadata = objectMapper.readTree(response.getBody());

        assertEquals("http://localhost:8085", metadata.get("issuer").asText());
        assertEquals(
                "http://localhost:8085/oauth2/authorize",
                metadata.get("authorization_endpoint").asText());
        assertEquals(
                "http://localhost:8085/oauth2/token",
                metadata.get("token_endpoint").asText());
        assertEquals(
                "http://localhost:8085/oauth2/jwks",
                metadata.get("jwks_uri").asText());
    }

    @Test
    void oidcDiscoveryEndpoint_shouldExposeExpectedConfiguration() throws Exception {
        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/.well-known/openid-configuration",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        JsonNode discovery = objectMapper.readTree(response.getBody());

        assertEquals("http://localhost:8085", discovery.get("issuer").asText());
        assertEquals(
                "http://localhost:8085/oauth2/authorize",
                discovery.get("authorization_endpoint").asText());
        assertEquals(
                "http://localhost:8085/oauth2/token",
                discovery.get("token_endpoint").asText());
        assertEquals(
                "http://localhost:8085/oauth2/jwks",
                discovery.get("jwks_uri").asText());

        assertTrue(discovery.has("userinfo_endpoint"));
        assertTrue(discovery.has("end_session_endpoint"));
        assertTrue(discovery.has("scopes_supported"));

        JsonNode scopes = discovery.get("scopes_supported");
        assertTrue(scopes.isArray());
        assertTrue(scopes.toString().contains("openid"));
    }

    @Test
    void jwksEndpoint_shouldReturnRsaKeyStructure() throws Exception {
        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/oauth2/jwks",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        JsonNode jwks = objectMapper.readTree(response.getBody());

        assertTrue(jwks.has("keys"));
        assertTrue(jwks.get("keys").isArray());
        assertFalse(jwks.get("keys").isEmpty());

        JsonNode key = jwks.get("keys").get(0);

        assertEquals("RSA", key.get("kty").asText());
        assertNotNull(key.get("kid"));
        assertFalse(key.get("kid").asText().isBlank());
        assertNotNull(key.get("n"));
        assertNotNull(key.get("e"));
    }

    @Test
    void authorizationEndpoint_shouldRequireAuthentication() {
        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/oauth2/authorize?response_type=code&client_id=iam-test-client&scope=openid&redirect_uri=http://localhost:8085/invalid",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("Sign in"));
        assertTrue(response.getBody().contains("username"));
    }

    @Test
    void oidcDiscovery_shouldExposeExpectedOauth2AndOidcEndpoints() throws Exception {
        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/.well-known/openid-configuration",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        JsonNode discovery = objectMapper.readTree(response.getBody());

        assertTrue(discovery.has("authorization_endpoint"));
        assertTrue(discovery.has("token_endpoint"));
        assertTrue(discovery.has("jwks_uri"));
        assertTrue(discovery.has("userinfo_endpoint"));
        assertTrue(discovery.has("end_session_endpoint"));
        assertTrue(discovery.has("revocation_endpoint"));
        assertTrue(discovery.has("introspection_endpoint"));
    }
}
