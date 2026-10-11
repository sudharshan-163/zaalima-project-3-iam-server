package com.zaalima.iam.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ConsentIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Consent UI: Renders consent page with single scope")
    @WithMockUser(username = "consent-test-user")
    void consentEndpoint_shouldRenderCustomConsentPage() throws Exception {
        mockMvc.perform(
                        get("/oauth2/consent")
                                .param("client_id", "iam-test-client")
                                .param("scope", "openid")
                                .param("state", "test-state"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Authorize Application")))
                .andExpect(content().string(containsString("Openid")))
                .andExpect(content().string(containsString("Authorize")))
                .andExpect(content().string(containsString("Deny")));
    }

    @Test
    @DisplayName("Consent UI: Correctly parses space-separated scopes and renders distinct checkboxes")
    @WithMockUser(username = "consent-test-user")
    void consentEndpoint_withSpaceSeparatedScopes_shouldRenderDistinctCheckboxes() throws Exception {
        mockMvc.perform(
                        get("/oauth2/consent")
                                .param("client_id", "iam-test-client")
                                .param("scope", "openid profile read")
                                .param("state", "test-state-space"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("value=\"openid\"")))
                .andExpect(content().string(containsString("value=\"profile\"")))
                .andExpect(content().string(containsString("value=\"read\"")))
                .andExpect(content().string(containsString("Verify your identity.")))
                .andExpect(content().string(containsString("Access your basic profile information.")))
                .andExpect(content().string(containsString("Read access to your account data.")));
    }

    @Test
    @DisplayName("Consent UI: Correctly handles comma-delimited fallback scopes")
    @WithMockUser(username = "consent-test-user")
    void consentEndpoint_withCommaSeparatedScopes_shouldRenderDistinctCheckboxes() throws Exception {
        mockMvc.perform(
                        get("/oauth2/consent")
                                .param("client_id", "iam-test-client")
                                .param("scope", "openid,profile")
                                .param("state", "test-state-comma"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("value=\"openid\"")))
                .andExpect(content().string(containsString("value=\"profile\"")));
    }

    @Test
    @DisplayName("Consent UI: Unauthenticated request redirects to login")
    void consentEndpoint_shouldRequireAuthentication() throws Exception {
        mockMvc.perform(
                        get("/oauth2/consent")
                                .param("client_id", "iam-test-client")
                                .param("scope", "openid")
                                .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }
}
