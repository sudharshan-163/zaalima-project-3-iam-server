package com.zaalima.iam.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenRevocationServiceTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOperations;
    private TokenRevocationService tokenRevocationService;

    @BeforeEach
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        valueOperations = mock(ValueOperations.class);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        tokenRevocationService =
                new TokenRevocationService(redisTemplate);
    }

    @Test
    void revoke_shouldStoreRevokedTokenWithTtl() {

        String jti = "test-jti";
        Duration ttl = Duration.ofMinutes(5);

        tokenRevocationService.revoke(jti, ttl);

        verify(valueOperations).set(
                "iam:revoked:" + jti,
                "revoked",
                ttl
        );
    }

    @Test
    void isRevoked_shouldReturnTrueWhenTokenExists() {

        String jti = "test-jti";

        when(redisTemplate.hasKey("iam:revoked:" + jti))
                .thenReturn(true);

        assertTrue(
                tokenRevocationService.isRevoked(jti)
        );
    }

    @Test
    void isRevoked_shouldReturnFalseWhenTokenDoesNotExist() {

        String jti = "test-jti";

        when(redisTemplate.hasKey("iam:revoked:" + jti))
                .thenReturn(false);

        assertFalse(
                tokenRevocationService.isRevoked(jti)
        );
    }

    @Test
    void clearRevocation_shouldDeleteRevocationKey() {

        String jti = "test-jti";

        tokenRevocationService.clearRevocation(jti);

        verify(redisTemplate).delete(
                "iam:revoked:" + jti
        );
    }

    @Test
    void revokeUntil_shouldStoreRevokedTokenWithRemainingTtl() {

        String jti = "test-jti";
        long expiresAt =
                java.time.Instant.now().getEpochSecond() + 300;

        tokenRevocationService.revokeUntil(jti, expiresAt);

        verify(valueOperations).set(
                eq("iam:revoked:" + jti),
                eq("revoked"),
                any(Duration.class)
        );
    }

    @Test
    void revokeUntil_shouldRejectExpiredToken() {

        String jti = "test-jti";
        long expiresAt =
                java.time.Instant.now().getEpochSecond() - 10;

        assertThrows(
                IllegalArgumentException.class,
                () -> tokenRevocationService.revokeUntil(
                        jti,
                        expiresAt
                )
        );
    }

    @Test
    void revokeUntil_shouldRejectInvalidExpiration() {

        String jti = "test-jti";

        assertThrows(
                IllegalArgumentException.class,
                () -> tokenRevocationService.revokeUntil(
                        jti,
                        0
                )
        );
    }

    @Test
    void revoke_shouldRejectBlankJti() {

        assertThrows(
                IllegalArgumentException.class,
                () -> tokenRevocationService.revoke(
                        "",
                        Duration.ofMinutes(5)
                )
        );
    }

    @Test
    void revoke_shouldRejectInvalidTtl() {

        assertThrows(
                IllegalArgumentException.class,
                () -> tokenRevocationService.revoke(
                        "test-jti",
                        Duration.ZERO
                )
        );
    }
}
