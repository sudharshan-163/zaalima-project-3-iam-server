package com.zaalima.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

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
    @WithMockUser(username = "consent-test-user")
    void consentEndpoint_shouldRenderCustomConsentPage() throws Exception {
        mockMvc.perform(
                        get("/oauth2/consent")
                                .param("client_id", "iam-test-client")
                                .param("scope", "openid")
                                .param("state", "test-state"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Authorize Application")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("OpenID")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Profile")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Authorize")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Deny")));
    }

    @Test
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

