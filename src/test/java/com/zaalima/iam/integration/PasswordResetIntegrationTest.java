package com.zaalima.iam.integration;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.PasswordResetTokenRepository;
import com.zaalima.iam.repository.UserRepository;
import com.zaalima.iam.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class PasswordResetIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;

    @BeforeEach
    void setUp() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();

        testUser = new User();
        testUser.setUsername("reset_user");
        testUser.setEmail("reset_user@example.com");
        testUser.setPassword(passwordEncoder.encode("OldPassword@123"));
        testUser.setEnabled(true);
        testUser = userRepository.save(testUser);
    }

    @Test
    @DisplayName("Should generate reset token and successfully update password")
    void shouldResetPasswordSuccessfully() {
        // 1. Generate token
        ForgotPasswordRequest forgotRequest = new ForgotPasswordRequest();
        forgotRequest.setEmail(testUser.getEmail());

        String generatedToken = assertDoesNotThrow(() -> userService.createPasswordResetToken(forgotRequest));
        assertNotNull(generatedToken, "Generated token must not be null");

        var tokenOpt = tokenRepository.findByToken(generatedToken);
        assertTrue(tokenOpt.isPresent(), "Reset token should be saved in DB");
        assertFalse(tokenOpt.get().isUsed(), "Token should not be used initially");

        // 2. Perform reset
        ResetPasswordRequest resetRequest = new ResetPasswordRequest();
        resetRequest.setToken(generatedToken);
        resetRequest.setPassword("NewStrongPassword@123");

        assertDoesNotThrow(() -> userService.resetPassword(resetRequest));

        // 3. Verify password updated in DB
        User updatedUser = userRepository.findByEmail("reset_user@example.com").orElseThrow();
        assertTrue(passwordEncoder.matches("NewStrongPassword@123", updatedUser.getPassword()));
        assertFalse(passwordEncoder.matches("OldPassword@123", updatedUser.getPassword()));

        // 4. Verify token marked as used
        var usedToken = tokenRepository.findByToken(generatedToken).orElseThrow();
        assertTrue(usedToken.isUsed(), "Token should be marked as used");
    }
}