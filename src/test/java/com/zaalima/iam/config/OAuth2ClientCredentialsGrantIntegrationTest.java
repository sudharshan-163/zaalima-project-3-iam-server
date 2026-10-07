package com.zaalima.iam.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2ClientCredentialsGrantIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String SERVICE_CLIENT_ID = "iam-service-client";
    private static final String SERVICE_CLIENT_SECRET = "iam-service-secret";

    @BeforeEach
    void setUp() {
        if (this.registeredClientRepository.findByClientId(SERVICE_CLIENT_ID) == null) {
            RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(SERVICE_CLIENT_ID)
                    .clientSecret(passwordEncoder.encode(SERVICE_CLIENT_SECRET))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("internal:read")
                    .scope("internal:write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(30))
                            .build())
                    .build();

            this.registeredClientRepository.save(serviceClient);
        }
    }

    @Test
    @DisplayName("Client Credentials Grant: Valid client credentials issue bearer access token without refresh token")
    void clientCredentials_validCredentials_shouldIssueAccessTokenWithoutRefreshToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal:read internal:write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").isNumber())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        String tokenValue = response.get("access_token").asText();

        Jwt decodedJwt = jwtDecoder.decode(tokenValue);
        assertNotNull(decodedJwt);
        assertEquals(SERVICE_CLIENT_ID, decodedJwt.getSubject(), "M2M token sub claim must match client_id");
        assertTrue(decodedJwt.getClaimAsStringList("scope").contains("internal:read"));
        assertTrue(decodedJwt.getClaimAsStringList("scope").contains("internal:write"));
    }

    @Test
    @DisplayName("Client Credentials Grant: Requesting downscoped authorization succeeds")
    void clientCredentials_downscopedRequest_shouldIssueTokenWithRequestedScopeOnly() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal:read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.scope").value("internal:read"))
                .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        Jwt decodedJwt = jwtDecoder.decode(response.get("access_token").asText());
        assertEquals(1, decodedJwt.getClaimAsStringList("scope").size());
        assertEquals("internal:read", decodedJwt.getClaimAsStringList("scope").get(0));
    }

    @Test
    @DisplayName("Client Credentials Grant: Unauthorized scope request is rejected with invalid_scope")
    void clientCredentials_unauthorizedScope_shouldReturnInvalidScope() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "admin:unauthorized-scope"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    @DisplayName("Client Credentials Grant: Invalid client secret is rejected with 401 Unauthorized")
    void clientCredentials_invalidSecret_shouldReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(SERVICE_CLIENT_ID, "wrong-password"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Client Credentials Grant: Form body authentication succeeds (RFC 6749)")
    void clientCredentials_formPostAuth_shouldSucceed() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("client_id", SERVICE_CLIENT_ID)
                        .param("client_secret", SERVICE_CLIENT_SECRET))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }
}