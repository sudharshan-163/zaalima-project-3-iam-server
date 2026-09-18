package com.zaalima.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthorizationServerIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void oidcDiscoveryEndpoint_shouldReturn200() {

        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/.well-known/openid-configuration",
                        String.class);

        assertEquals(200, response.getStatusCode().value());
        assertTrue(response.getBody().contains("\"issuer\""));
        assertTrue(response.getBody().contains("\"authorization_endpoint\""));
        assertTrue(response.getBody().contains("\"token_endpoint\""));
        assertTrue(response.getBody().contains("\"jwks_uri\""));
    }

    @Test
    void jwksEndpoint_shouldReturn200() {

        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/oauth2/jwks",
                        String.class);

        assertEquals(200, response.getStatusCode().value());
        assertTrue(response.getBody().contains("\"keys\""));
        assertTrue(response.getBody().contains("\"RSA\""));
    }
}

