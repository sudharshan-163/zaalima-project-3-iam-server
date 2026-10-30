package com.zaalima.iam.integration;

import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import com.zaalima.iam.service.LoginAttemptService;
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
class AccountLockoutIntegrationTest {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        testUser = new User();
        testUser.setUsername("lockout_test_user");
        testUser.setEmail("lockout@example.com");
        testUser.setPassword(passwordEncoder.encode("Password@123"));
        testUser.setEnabled(true);
        testUser.setAccountNonLocked(true);
        testUser.setFailedLoginAttempts(0);
        testUser = userRepository.save(testUser);
    }

    @Test
    @DisplayName("Should lock account after 5 consecutive failed login attempts")
    void shouldLockAccountAfterMaxFailedAttempts() {
        // Trigger 4 failed attempts
        for (int i = 1; i <= 4; i++) {
            loginAttemptService.loginFailed(testUser.getUsername());
            User u = userRepository.findByUsername(testUser.getUsername()).orElseThrow();
            assertEquals(i, u.getFailedLoginAttempts());
            assertTrue(u.isAccountNonLocked(), "Account should still be unlocked after " + i + " attempts");
        }

        // 5th failed attempt triggers lockout
        loginAttemptService.loginFailed(testUser.getUsername());
        User lockedUser = userRepository.findByUsername(testUser.getUsername()).orElseThrow();
        assertEquals(5, lockedUser.getFailedLoginAttempts());
        assertFalse(lockedUser.isAccountNonLocked(), "Account must be locked after 5 failed attempts");
        assertNotNull(lockedUser.getLockoutExpiration(), "Lockout expiration timestamp must be populated");
    }

    @Test
    @DisplayName("Successful login should reset failed attempt count and keep account unlocked")
    void shouldResetAttemptsOnLoginSuccess() {
        loginAttemptService.loginFailed(testUser.getUsername());
        loginAttemptService.loginFailed(testUser.getUsername());

        User userAfterFails = userRepository.findByUsername(testUser.getUsername()).orElseThrow();
        assertEquals(2, userAfterFails.getFailedLoginAttempts());

        // Successful login
        loginAttemptService.loginSucceeded(testUser.getUsername());

        User userAfterSuccess = userRepository.findByUsername(testUser.getUsername()).orElseThrow();
        assertEquals(0, userAfterSuccess.getFailedLoginAttempts(), "Counter must be reset to 0");
        assertTrue(userAfterSuccess.isAccountNonLocked(), "Account must remain unlocked");
    }
}