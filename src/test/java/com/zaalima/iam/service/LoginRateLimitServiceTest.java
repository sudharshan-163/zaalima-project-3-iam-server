package com.zaalima.iam.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
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

    @Test
    @DisplayName("Attempts 1 to 5 are allowed and 6th attempt is blocked for same IP and username")
    void shouldAllowFirstFiveAttemptsAndBlockSixth() {
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

    @Test
    @DisplayName("IP blocked after 5 attempts across different usernames from the same IP (anti-spraying)")
    void shouldBlockIpAfterFiveAttemptsAcrossDifferentUsernames() {
        String ip = randomIp();
        for (int i = 1; i <= 5; i++) {
            String user = randomUser();
            registerForCleanup(ip, user);
            assertTrue(
                    loginRateLimitService.isAllowed(ip, user),
                    "Attempt " + i + " on IP with distinct username should be allowed"
            );
        }

        String sixthUser = randomUser();
        registerForCleanup(ip, sixthUser);
        assertFalse(
                loginRateLimitService.isAllowed(ip, sixthUser),
                "Sixth attempt from same IP must be blocked to prevent password-spraying"
        );
    }

    @Test
    @DisplayName("Same username from different IPs has independent IP limits")
    void shouldMaintainIndependentLimitsForSameUserAcrossDifferentIps() {
        String ip1 = "192.0.2.201";
        String ip2 = "192.0.2.202";
        String username = randomUser();
        registerForCleanup(ip1, username);
        registerForCleanup(ip2, username);

        for (int i = 1; i <= 5; i++) {
            assertTrue(loginRateLimitService.isAllowed(ip1, username));
        }
        assertFalse(loginRateLimitService.isAllowed(ip1, username), "IP 1 must be blocked");

        assertTrue(
                loginRateLimitService.isAllowed(ip2, username),
                "IP 2 must remain allowed for the same username"
        );
    }

    @Test
    @DisplayName("Different IP and username combinations maintain isolated buckets")
    void shouldIsolateDifferentIpAndUsernameCombinations() {
        String ipA = "198.51.100.31";
        String ipB = "198.51.100.32";
        String userA = randomUser();
        String userB = randomUser();
        registerForCleanup(ipA, userA);
        registerForCleanup(ipB, userB);

        for (int i = 1; i <= 5; i++) {
            assertTrue(loginRateLimitService.isAllowed(ipA, userA));
        }
        assertFalse(loginRateLimitService.isAllowed(ipA, userA));

        for (int i = 1; i <= 5; i++) {
            assertTrue(
                    loginRateLimitService.isAllowed(ipB, userB),
                    "Bucket for ipB:userB must be independent of ipA:userA"
            );
        }
        assertFalse(loginRateLimitService.isAllowed(ipB, userB));
    }

    @Test
    @DisplayName("Both account key and IP key are created with valid TTL (<= 60s)")
    void shouldCreateBothKeysWithExpectedTtl() {
        String ip = "10.0.0.99";
        String username = "dual_key_user";
        registerForCleanup(ip, username);

        String expectedAccountKey = KEY_PREFIX + sha256(ip + ":" + username);
        String expectedIpKey = IP_KEY_PREFIX + sha256(ip);

        assertTrue(loginRateLimitService.isAllowed(ip, username));

        assertEquals("1", redisTemplate.opsForValue().get(expectedAccountKey));
        assertEquals("1", redisTemplate.opsForValue().get(expectedIpKey));

        Long accountTtl = redisTemplate.getExpire(expectedAccountKey, TimeUnit.SECONDS);
        Long ipTtl = redisTemplate.getExpire(expectedIpKey, TimeUnit.SECONDS);

        assertNotNull(accountTtl);
        assertNotNull(ipTtl);
        assertTrue(accountTtl > 0 && accountTtl <= 60, "Account key TTL must be <= 60s");
        assertTrue(ipTtl > 0 && ipTtl <= 60, "IP key TTL must be <= 60s");
    }

    @Test
    @DisplayName("reset(ip, username) clears keys and allows a new login window")
    void shouldClearRateLimitStateAndAllowNewWindow() {
        String ip = randomIp();
        String username = randomUser();

        String accountKey = KEY_PREFIX + sha256(ip + ":" + username);
        String ipKey = IP_KEY_PREFIX + sha256(ip);

        for (int i = 0; i < 5; i++) {
            loginRateLimitService.isAllowed(ip, username);
        }
        assertFalse(loginRateLimitService.isAllowed(ip, username));

        loginRateLimitService.reset(ip, username);

        assertNull(redisTemplate.opsForValue().get(accountKey), "Account key must be removed");
        assertNull(redisTemplate.opsForValue().get(ipKey), "IP key must be removed");

        assertTrue(
                loginRateLimitService.isAllowed(ip, username),
                "Request must be allowed immediately after reset"
        );
    }

    @Test
    @DisplayName("Request denied if account counter breaches threshold independently")
    void shouldDenyIfAccountCounterExceedsThreshold() {
        String ip = randomIp();
        String username = randomUser();
        registerForCleanup(ip, username);

        String accountKey = KEY_PREFIX + sha256(ip + ":" + username);
        redisTemplate.opsForValue().set(accountKey, "5");

        assertFalse(
                loginRateLimitService.isAllowed(ip, username),
                "Should block when account bucket exceeds 5"
        );
    }

    @Test
    @DisplayName("Request denied if IP counter breaches threshold independently")
    void shouldDenyIfIpCounterExceedsThreshold() {
        String ip = randomIp();
        String username = randomUser();
        registerForCleanup(ip, username);

        String ipKey = IP_KEY_PREFIX + sha256(ip);
        redisTemplate.opsForValue().set(ipKey, "5");

        assertFalse(
                loginRateLimitService.isAllowed(ip, username),
                "Should block when IP bucket exceeds 5"
        );
    }

    @Test
    @DisplayName("Null username handled gracefully without exception")
    void shouldHandleNullUsernameGracefully() {
        String ip = randomIp();
        registerForCleanup(ip, null);

        for (int i = 1; i <= 5; i++) {
            assertTrue(loginRateLimitService.isAllowed(ip, null));
        }
        assertFalse(loginRateLimitService.isAllowed(ip, null));
    }
}