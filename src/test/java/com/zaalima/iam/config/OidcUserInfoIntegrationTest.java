package com.zaalima.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OidcUserInfoIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void userInfoEndpoint_shouldRequireAuthentication() {

        ResponseEntity<String> response =
                restTemplate.getForEntity(
                        "/userinfo",
                        String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("Sign in"));
    }
}
