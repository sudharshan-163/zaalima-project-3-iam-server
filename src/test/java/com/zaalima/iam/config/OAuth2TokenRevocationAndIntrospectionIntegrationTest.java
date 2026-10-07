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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2TokenRevocationAndIntrospectionIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String CLIENT_ID = "revocation-test-client";
    private static final String CLIENT_SECRET = "revocation-test-secret";
    private static final String REDIRECT_URI = "http://localhost:8085/oauth2/callback";
    private static final String STATE = "revocation-test-state";

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

    private JsonNode obtainTokens() throws Exception {
        String codeVerifier = "code-verifier-string-123456789012345678901234567890";
        String codeChallenge = generateCodeChallenge(codeVerifier);

        MockHttpSession session = new MockHttpSession();

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

        return objectMapper.readTree(tokenResult.getResponse().getContentAsString());
    }

    @Test
    @WithMockUser(username = "revocation-user", roles = {"USER"})
    @DisplayName("Token Introspection: Active access token returns active=true and metadata (RFC 7662)")
    void introspect_activeAccessToken_shouldReturnActiveTrue() throws Exception {
        JsonNode tokens = obtainTokens();
        String accessToken = tokens.get("access_token").asText();

        mockMvc.perform(post("/oauth2/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", accessToken)
                        .param("token_type_hint", "access_token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value(CLIENT_ID))
                .andExpect(jsonPath("$.sub").value("revocation-user"));
    }

    @Test
    @WithMockUser(username = "revocation-user", roles = {"USER"})
    @DisplayName("Token Introspection: Active refresh token returns active=true (RFC 7662)")
    void introspect_activeRefreshToken_shouldReturnActiveTrue() throws Exception {
        JsonNode tokens = obtainTokens();
        String refreshToken = tokens.get("refresh_token").asText();

        mockMvc.perform(post("/oauth2/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", refreshToken)
                        .param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value(CLIENT_ID));
    }

    @Test
    @WithMockUser(username = "revocation-user", roles = {"USER"})
    @DisplayName("Token Revocation: Revoking refresh token succeeds with 200 OK and marks token inactive (RFC 7009)")
    void revoke_refreshToken_shouldSucceedAndMarkInactive() throws Exception {
        JsonNode tokens = obtainTokens();
        String refreshToken = tokens.get("refresh_token").asText();

        // 1. Revoke the refresh token
        mockMvc.perform(post("/oauth2/revoke")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", refreshToken)
                        .param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk());

        // 2. Introspection should now show active=false
        mockMvc.perform(post("/oauth2/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", refreshToken)
                        .param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        // 3. Attempting to use the revoked refresh token must be rejected with invalid_grant
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Token Revocation: Revoking an unknown or invalid token still returns 200 OK (RFC 7009)")
    void revoke_unknownToken_shouldReturn200Ok() throws Exception {
        mockMvc.perform(post("/oauth2/revoke")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", "completely-bogus-token-value")
                        .param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Token Introspection: Unknown token returns active=false (RFC 7662)")
    void introspect_unknownToken_shouldReturnActiveFalse() throws Exception {
        mockMvc.perform(post("/oauth2/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", "completely-bogus-token-value"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }
}