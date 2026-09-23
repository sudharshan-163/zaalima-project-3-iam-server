package com.zaalima.iam.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final String KEY_PREFIX = "iam:revoked:";

    private final StringRedisTemplate redisTemplate;

    public void revoke(String jti, Duration ttl) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("Token jti must not be blank");
        }

        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("Revocation TTL must be positive");
        }

        redisTemplate.opsForValue().set(
                KEY_PREFIX + jti,
                "revoked",
                ttl
        );
    }

    public void revokeUntil(String jti, long expiresAt) {
        if (expiresAt <= 0) {
            throw new IllegalArgumentException(
                    "Token expiration time must be positive");
        }

        long remainingSeconds =
                expiresAt - java.time.Instant.now().getEpochSecond();

        if (remainingSeconds <= 0) {
            throw new IllegalArgumentException(
                    "Token has already expired");
        }

        revoke(jti, Duration.ofSeconds(remainingSeconds));
    }

    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }

        return Boolean.TRUE.equals(
                redisTemplate.hasKey(KEY_PREFIX + jti)
        );
    }

    public void clearRevocation(String jti) {
        if (jti != null && !jti.isBlank()) {
            redisTemplate.delete(KEY_PREFIX + jti);
        }
    }
}
