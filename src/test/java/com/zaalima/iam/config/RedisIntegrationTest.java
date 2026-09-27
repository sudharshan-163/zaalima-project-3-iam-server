package com.zaalima.iam.config;

import com.zaalima.iam.security.RedisJwtAuthenticationConverter;
import com.zaalima.iam.service.TokenRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SpringBootTest
class RedisIntegrationTest {

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private RedisJwtAuthenticationConverter jwtAuthenticationConverter;

    @BeforeEach
    void verifyRedisAvailability() {
        boolean redisAvailable = false;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 6379), 200);
            redisAvailable = true;
        } catch (Exception ignored) {
        }
        assumeTrue(redisAvailable, "Local Redis daemon is not reachable on 127.0.0.1:6379 - skipping integration test");
    }

    @Test
    void shouldWriteAndReadFromRedis() {
        String key = "iam:test:redis";
        String value = "redis-connected";

        try {
            redisTemplate.opsForValue().set(key, value);

            String result = redisTemplate.opsForValue().get(key);

            assertEquals(value, result);
        } finally {
            redisTemplate.delete(key);
        }
    }

    @Test
    void revokedJwtShouldBeRejectedByAuthenticationConverter() {
        String jti = "revocation-integration-" + UUID.randomUUID();
        Instant now = Instant.now();

        Jwt jwt = Jwt.withTokenValue("integration-test-token")
                .header("alg", "none")
                .claim("jti", jti)
                .subject("revocation-test-user")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();

        try {
            tokenRevocationService.revokeUntil(
                    jti,
                    now.plusSeconds(300).getEpochSecond()
            );

            assertThrows(
                    InvalidBearerTokenException.class,
                    () -> jwtAuthenticationConverter.convert(jwt)
            );
        } finally {
            tokenRevocationService.clearRevocation(jti);
        }
    }
}
