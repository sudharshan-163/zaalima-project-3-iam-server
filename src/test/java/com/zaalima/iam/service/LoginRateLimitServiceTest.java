package com.zaalima.iam.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class LoginRateLimitServiceTest {

    private static final String KEY_PREFIX = "iam:rate-limit:login:";
    private static final String IP_KEY_PREFIX = "iam:rate-limit:login-ip:";

    @Autowired
    private LoginRateLimitService loginRateLimitService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    private final List<String[]> trackForCleanup = new ArrayList<>();

    @AfterEach
    void cleanup() {
        for (String[] pair : trackForCleanup) {
            loginRateLimitService.reset(pair[0], pair[1]);
        }
        trackForCleanup.clear();
    }

    private String randomIp() {
        return "198.51.100." + (int) (Math.random() * 200 + 10);
    }

    private String randomUser() {
        return "user_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private void registerForCleanup(String ip, String username) {
        trackForCleanup.add(new String[]{ip, username});
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Nested
    @DisplayName("Threshold Verification (5 Allowed, 6th Blocked)")
    class ThresholdTests {

        @Test
        @DisplayName("Should allow exactly first 5 login attempts and block the 6th")
        void shouldAllowFirstFiveLoginAttemptsAndBlockSixth() {
            String ip = randomIp();
            String username = randomUser();
            registerForCleanup(ip, username);

            for (int attempt = 1; attempt <= 5; attempt++) {
                assertTrue(
                        loginRateLimitService.isAllowed(ip, username),
                        "Attempt " + attempt + " should be allowed"
                );
            }

            assertFalse(
                    loginRateLimitService.isAllowed(ip, username),
                    "Sixth attempt should be blocked"
            );
        }
    }

    @Nested
    @DisplayName("IP and Account Isolation")
    class IsolationTests {

        @Test
        @DisplayName("Should maintain independent limits for different IP addresses")
        void shouldKeepIndependentLimitsForDifferentIps() {
            String ipA = "192.0.2.101";
            String ipB = "192.0.2.102";
            String username = randomUser();
            registerForCleanup(ipA, username);
            registerForCleanup(ipB, username);

            for (int attempt = 1; attempt <= 5; attempt++) {
                assertTrue(loginRateLimitService.isAllowed(ipA, username));
            }
            assertFalse(loginRateLimitService.isAllowed(ipA, username), "IP A must be blocked after 5 attempts");

            assertTrue(
                    loginRateLimitService.isAllowed(ipB, username),
                    "IP B must remain allowed even if IP A exceeded its threshold"
            );
        }

        @Test
        @DisplayName("Should block IP after 5 attempts across different usernames (anti-spraying)")
        void shouldBlockIpAfterFiveAttemptsAcrossDifferentUsernames() {
            String ip = randomIp();
            for (int i = 1; i <= 5; i++) {
                String user = randomUser();
                registerForCleanup(ip, user);
                assertTrue(loginRateLimitService.isAllowed(ip, user), "Attempt " + i + " on IP should be allowed");
            }

            String sixthUser = randomUser();
            registerForCleanup(ip, sixthUser);
            assertFalse(
                    loginRateLimitService.isAllowed(ip, sixthUser),
                    "Sixth attempt from same IP must be blocked across different accounts"
            );
        }

        @Test
        @DisplayName("Should allow same username from a different IP when not exceeding limits")
        void shouldAllowSameUsernameFromDifferentIp() {
            String ip1 = "198.51.100.51";
            String ip2 = "198.51.100.52";
            String username = randomUser();
            registerForCleanup(ip1, username);
            registerForCleanup(ip2, username);

            for (int i = 1; i <= 5; i++) {
                assertTrue(loginRateLimitService.isAllowed(ip1, username));
            }
            assertFalse(loginRateLimitService.isAllowed(ip1, username));

            assertTrue(
                    loginRateLimitService.isAllowed(ip2, username),
                    "Different client IP should have independent rate limit for user"
            );
        }
    }

    @Nested
    @DisplayName("Redis Key Generation and TTL Window")
    class RedisKeyAndTtlTests {

        @Test
        @DisplayName("Should create Redis keys matching exact SHA-256 hashed pattern")
        void shouldCreateExactHashedRedisKeys() {
            String ip = "10.10.10.5";
            String username = "exact_key_user";
            registerForCleanup(ip, username);

            String expectedAccountKey = KEY_PREFIX + sha256(ip + ":" + username);
            String expectedIpKey = IP_KEY_PREFIX + sha256(ip);

            assertTrue(loginRateLimitService.isAllowed(ip, username));

            assertEquals("1", redisTemplate.opsForValue().get(expectedAccountKey));
            assertEquals("1", redisTemplate.opsForValue().get(expectedIpKey));
        }

        @Test
        @DisplayName("Should set 60-second window expiry (TTL) on Redis keys")
        void shouldSetValidTtlOnRedisKeys() {
            String ip = randomIp();
            String username = randomUser();
            registerForCleanup(ip, username);

            String accountKey = KEY_PREFIX + sha256(ip + ":" + username);
            String ipKey = IP_KEY_PREFIX + sha256(ip);

            assertTrue(loginRateLimitService.isAllowed(ip, username));

            Long accountTtl = redisTemplate.getExpire(accountKey, TimeUnit.SECONDS);
            Long ipTtl = redisTemplate.getExpire(ipKey, TimeUnit.SECONDS);

            assertNotNull(accountTtl);
            assertNotNull(ipTtl);
            assertTrue(accountTtl > 0 && accountTtl <= 60, "Account key TTL should be within 60s window");
            assertTrue(ipTtl > 0 && ipTtl <= 60, "IP key TTL should be within 60s window");
        }

        @Test
        @DisplayName("Should delete both account and IP Redis keys upon reset")
        void shouldDeleteKeysUponReset() {
            String ip = randomIp();
            String username = randomUser();

            String accountKey = KEY_PREFIX + sha256(ip + ":" + username);
            String ipKey = IP_KEY_PREFIX + sha256(ip);

            for (int i = 0; i < 5; i++) {
                loginRateLimitService.isAllowed(ip, username);
            }
            assertFalse(loginRateLimitService.isAllowed(ip, username));

            loginRateLimitService.reset(ip, username);

            assertNull(redisTemplate.opsForValue().get(accountKey), "Account key should be deleted");
            assertNull(redisTemplate.opsForValue().get(ipKey), "IP key should be deleted");

            assertTrue(loginRateLimitService.isAllowed(ip, username), "Subsequent request should be allowed after reset");
        }
    }

    @Nested
    @DisplayName("Edge Cases & Null Safety")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null username gracefully without throwing exception")
        void shouldHandleNullUsernameGracefully() {
            String ip = randomIp();
            registerForCleanup(ip, null);

            for (int i = 1; i <= 5; i++) {
                assertTrue(loginRateLimitService.isAllowed(ip, null));
            }
            assertFalse(loginRateLimitService.isAllowed(ip, null));
        }
    }
}