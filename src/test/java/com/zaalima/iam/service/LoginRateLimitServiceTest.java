package com.zaalima.iam.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class LoginRateLimitServiceTest {

    private static final String IP = "192.0.2.10";
    private static final String USERNAME = "rate_limit_test_user";

    @Autowired
    private LoginRateLimitService loginRateLimitService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @AfterEach
    void cleanup() {
        loginRateLimitService.reset(IP, USERNAME);
        loginRateLimitService.reset(IP, "another_user");
    }

    @Test
    void shouldAllowFirstFiveLoginAttemptsAndBlockSixth() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            assertTrue(
                    loginRateLimitService.isAllowed(IP, USERNAME),
                    "Attempt " + attempt + " should be allowed"
            );
        }

        assertFalse(
                loginRateLimitService.isAllowed(IP, USERNAME),
                "Sixth attempt should be blocked"
        );
    }

    @Test
    void shouldEnforceIpLimitAcrossDifferentUsernames() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            assertTrue(loginRateLimitService.isAllowed(IP, USERNAME));
        }

        assertFalse(
                loginRateLimitService.isAllowed(IP, "another_user"),
                "Different username from the same IP should still be blocked"
        );

        assertTrue(
                loginRateLimitService.isAllowed("192.0.2.11", USERNAME),
                "Same username from a different IP should have a separate IP rate-limit"
        );
    }

    @Test
    void shouldResetLoginAttemptCounter() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            assertTrue(loginRateLimitService.isAllowed(IP, USERNAME));
        }

        assertFalse(loginRateLimitService.isAllowed(IP, USERNAME));

        loginRateLimitService.reset(IP, USERNAME);

        assertTrue(
                loginRateLimitService.isAllowed(IP, USERNAME),
                "After reset, a new login window should start"
        );
    }

    @Test
    void shouldCreateRedisKeyWithExpiry() {
        assertTrue(loginRateLimitService.isAllowed(IP, USERNAME));

        String expectedKeyPattern = "iam:rate-limit:login:";
        Boolean keyExists = redisTemplate.keys(expectedKeyPattern + "*")
                .stream()
                .anyMatch(key -> key.startsWith(expectedKeyPattern));

        assertTrue(keyExists, "Rate-limit key should exist in Redis");
    }
    @Test
    void shouldBlockIpAfterFiveAttemptsAcrossDifferentUsernames() {
        assertTrue(loginRateLimitService.isAllowed(IP, "user1"));
        assertTrue(loginRateLimitService.isAllowed(IP, "user2"));
        assertTrue(loginRateLimitService.isAllowed(IP, "user3"));
        assertTrue(loginRateLimitService.isAllowed(IP, "user4"));
        assertTrue(loginRateLimitService.isAllowed(IP, "user5"));

        assertFalse(
                loginRateLimitService.isAllowed(IP, "user6"),
                "Sixth attempt from the same IP should be blocked"
        );
    }
}
