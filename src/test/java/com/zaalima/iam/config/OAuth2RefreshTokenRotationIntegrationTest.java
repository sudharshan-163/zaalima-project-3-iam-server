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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2RefreshTokenRotationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String CLIENT_ID = "rotation-test-client";
    private static final String CLIENT_SECRET = "rotation-test-secret";
    private static final String REDIRECT_URI = "http://localhost:8085/oauth2/callback";
    private static final String STATE = "rotation-test-state";

    @BeforeEach
    void setUp() {
        if (this.registeredClientRepository.findByClientId(CLIENT_ID) == null) {
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(CLIENT_ID)
                    .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .scope("profile")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .reuseRefreshTokens(false)
                            .refreshTokenTimeToLive(Duration.ofDays(30))
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .build())
                    .build();

            this.registeredClientRepository.save(client);
        }
    }

    private String generateCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String obtainInitialRefreshToken() throws Exception {
        String codeVerifier = "code-verifier-string-123456789012345678901234567890";
        String codeChallenge = generateCodeChallenge(codeVerifier);

        MockHttpSession session = new MockHttpSession();

        // 1. Authorize request with PKCE and MockUser - directly redirects to REDIRECT_URI with code
        MvcResult authResult = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid profile")
                        .queryParam("state", STATE)
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String callbackUrl = authResult.getResponse().getRedirectedUrl();
        assertNotNull(callbackUrl);

        Matcher matcher = Pattern.compile("code=([^&]+)").matcher(callbackUrl);
        assertTrue(matcher.find(), "Authorization code must be present in callback URL");
        String authorizationCode = matcher.group(1);

        // 2. Exchange authorization code for initial token pair
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", authorizationCode)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", codeVerifier))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();

        JsonNode responseJson = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        return responseJson.get("refresh_token").asText();
    }

    @Test
    @WithMockUser(username = "rotation-user", roles = {"USER"})
    @DisplayName("Refresh Token Rotation: Valid refresh token grants new access token and rotated refresh token")
    void refreshToken_shouldRotateRefreshToken_andIssueNewAccessToken() throws Exception {
        String initialRefreshToken = obtainInitialRefreshToken();

        // 1st Refresh: Rotate token
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", initialRefreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();

        JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
        String rotatedRefreshToken = responseJson.get("refresh_token").asText();

        // Verify rotation: new token must not equal initial token
        assertNotEquals(initialRefreshToken, rotatedRefreshToken, "Refresh token must be rotated upon use");

        // The newly rotated token should be usable for subsequent refresh
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", rotatedRefreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty());
    }

    @Test
    @WithMockUser(username = "rotation-user", roles = {"USER"})
    @DisplayName("Refresh Token Reuse Detection: Previously rotated refresh token cannot be reused")
    void reusedRefreshToken_shouldBeRejectedWithInvalidGrant() throws Exception {
        String initialRefreshToken = obtainInitialRefreshToken();

        // 1st consumption: Rotates the token
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", initialRefreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty());

        // Replay attempt: Old refresh token must be rejected with 400 invalid_grant
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", initialRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Refresh Token: Unknown or bogus token is rejected with invalid_grant")
    void bogusRefreshToken_shouldBeRejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "completely-bogus-token-value"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}