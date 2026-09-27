package com.zaalima.iam.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaalima.iam.dto.TokenRevocationRequest;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import com.zaalima.iam.service.TokenRevocationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TokenRevocationEndToEndIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String lastRevokedJti;
    private boolean createdClientUser;

    @BeforeEach
    void setUp() {
        if (userRepository.findByUsername("iam-test-client").isEmpty()) {
            User user = new User();
            user.setUsername("iam-test-client");
            user.setEmail("iam-test-client@example.com");
            user.setPassword(passwordEncoder.encode("TestClient@123"));
            user.setEnabled(true);
            userRepository.save(user);
            createdClientUser = true;
        }
    }

    @AfterEach
    void cleanUp() {
        if (lastRevokedJti != null) {
            tokenRevocationService.clearRevocation(lastRevokedJti);
            lastRevokedJti = null;
        }
        if (createdClientUser) {
            userRepository.findByUsername("iam-test-client").ifPresent(userRepository::delete);
            createdClientUser = false;
        }
    }

    @Test
    void endToEnd_tokenRevocation_shouldRejectRevokedTokenInResourceServer() throws Exception {
        // Step 1: Issue token via client_credentials grant
        String basicAuth = Base64.getEncoder().encodeToString(
                "iam-test-client:iam-test-secret".getBytes(StandardCharsets.UTF_8));

        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basicAuth)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "openid profile"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andReturn();

        JsonNode tokenJson = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        String accessToken = tokenJson.get("access_token").asText();
        assertNotNull(accessToken);

        // Step 2: Decode token and verify jti exists
        Jwt decodedJwt = jwtDecoder.decode(accessToken);
        String jti = decodedJwt.getId();
        long expiresAtEpochSec = Objects.requireNonNullElseGet(
                decodedJwt.getExpiresAt(),
                () -> Instant.now().plusSeconds(300)
        ).getEpochSecond();

        assertNotNull(jti, "JWT should contain a jti claim");
        assertFalse(tokenRevocationService.isRevoked(jti), "Newly issued token should not be revoked");

        // Step 3: Access resource server endpoint before revocation (should succeed)
        mockMvc.perform(get("/api/users/by-username/iam-test-client")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("iam-test-client"));

        // Step 4: Revoke the token
        lastRevokedJti = jti;
        TokenRevocationRequest revokeRequest = new TokenRevocationRequest();
        revokeRequest.setJti(jti);
        revokeRequest.setExpiresAt(expiresAtEpochSec);

        tokenRevocationService.revokeUntil(revokeRequest.getJti(), revokeRequest.getExpiresAt());

        assertTrue(tokenRevocationService.isRevoked(jti), "Token should be marked as revoked in Redis");

        // Step 5: Access resource server endpoint again with revoked token (should be rejected)
        mockMvc.perform(get("/api/users/by-username/iam-test-client")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("revoked")));
    }
}
