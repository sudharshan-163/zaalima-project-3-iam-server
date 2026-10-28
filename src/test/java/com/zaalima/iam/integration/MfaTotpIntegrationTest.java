package com.zaalima.iam.integration;

import com.zaalima.iam.entity.MfaCredential;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.MfaCredentialRepository;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class MfaTotpIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MfaCredentialRepository mfaCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final String secretKey = "M3QZUMMJGWB6PZM537OJUTOTWLRBKHW4";

    @BeforeEach
    void setUp() {
        mfaCredentialRepository.deleteAll();
        userRepository.deleteAll();

        User testUser = new User();
        testUser.setUsername("mfa_auto_user");
        testUser.setEmail("mfa_auto@example.com");
        testUser.setPassword(passwordEncoder.encode("Test@123"));
        testUser.setEnabled(true);
        testUser = userRepository.save(testUser);

        MfaCredential credential = new MfaCredential();
        credential.setUser(testUser);
        credential.setSecret(secretKey);
        credential.setEnabled(true);
        credential.setCreatedAt(LocalDateTime.now());
        credential.setUpdatedAt(LocalDateTime.now());
        mfaCredentialRepository.save(credential);
    }

    @Test
    @DisplayName("Primary login should redirect to /mfa when MFA is enabled")
    void shouldRedirectToMfaOnPrimaryLogin() throws Exception {
        mockMvc.perform(post("/login")
                .param("username", "mfa_auto_user")
                .param("password", "Test@123")
                .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/mfa"));
    }

    @Test
    @DisplayName("Submitting invalid TOTP code should redirect to /mfa with error flash attribute")
    void shouldRejectInvalidTotpCode() throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/login")
                .param("username", "mfa_auto_user")
                .param("password", "Test@123")
                .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession();

        mockMvc.perform(post("/mfa")
                .session(session)
                .param("code", "000000")
                .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/mfa"))
                .andExpect(flash().attribute("error", "Invalid or expired MFA code."));
    }
}