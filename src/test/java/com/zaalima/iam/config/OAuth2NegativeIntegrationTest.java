package com.zaalima.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2NegativeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "oauth2-test-user")
    void authorizationEndpoint_shouldRejectUnknownClient() throws Exception {
        mockMvc.perform(
                        get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "unknown-client")
                                .param("scope", "openid")
                                .param("redirect_uri", "http://localhost:8085/oauth2/callback"))
                .andExpect(status().isBadRequest());
    }
}
