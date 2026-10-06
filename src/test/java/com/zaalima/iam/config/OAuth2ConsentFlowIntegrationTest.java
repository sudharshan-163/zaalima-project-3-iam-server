package com.zaalima.iam.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2ConsentFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String CLIENT_ID = "iam-test-client";
    private static final String REDIRECT_URI = "http://localhost:8085/oauth2/callback";
    private static final String STATE = "xyz123";

    private String generateCodeChallenge(String verifier) throws Exception {
        byte[] bytes = verifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @Test
    @DisplayName("OAuth2 Flow: Authenticated user initiating authorization code flow is redirected to consent page")
    @WithMockUser(username = "consent-user", roles = {"USER"})
    void authorizationRequest_withValidPkce_shouldRedirectToConsentPage() throws Exception {
        String codeVerifier = "code-verifier-string-123456789012345678901234567890";
        String codeChallenge = generateCodeChallenge(codeVerifier);

        mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid profile")
                        .queryParam("state", STATE)
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/consent")))
                .andExpect(header().string("Location", containsString("client_id=" + CLIENT_ID)))
                .andExpect(header().string("Location", anyOf(
                        containsString("scope=openid%20profile"),
                        containsString("scope=openid+profile")
                )));
    }

    @Test
    @DisplayName("OAuth2 Flow: Unauthenticated authorization request redirects to login page")
    void authorizationRequest_unauthenticated_shouldRedirectToLogin() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid")
                        .queryParam("state", STATE))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login")));
    }

    @Test
    @DisplayName("Consent UI: Rendered consent form contains approve/deny controls and client metadata")
    @WithMockUser(username = "consent-user", roles = {"USER"})
    void consentPage_shouldRenderApproveAndDenyControlsWithClientDetails() throws Exception {
        mockMvc.perform(get("/oauth2/consent")
                        .param("client_id", CLIENT_ID)
                        .param("scope", "openid profile")
                        .param("state", STATE))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Authorize Application")))
                .andExpect(content().string(containsString(CLIENT_ID)))
                .andExpect(content().string(containsString("OpenID")))
                .andExpect(content().string(containsString("Profile")))
                .andExpect(content().string(containsString("Authorize")))
                .andExpect(content().string(containsString("Deny")))
                .andExpect(content().string(containsString("cancelConsent()")));
    }

    @Test
    @DisplayName("OAuth2 Flow: Invalid client_id should be rejected with 400 Bad Request")
    @WithMockUser(username = "consent-user", roles = {"USER"})
    void authorizationRequest_withInvalidClientId_shouldReturnBadRequest() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "non-existent-client")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid")
                        .queryParam("state", STATE))
                .andExpect(status().isBadRequest());
    }
}