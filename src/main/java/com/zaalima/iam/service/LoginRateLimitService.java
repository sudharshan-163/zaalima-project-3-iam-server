package com.zaalima.iam.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;

@Service
@RequiredArgsConstructor
public class LoginRateLimitService {

    private static final String KEY_PREFIX = "iam:rate-limit:login:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private static final String RATE_LIMIT_SCRIPT = """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            """;

    private final StringRedisTemplate redisTemplate;

    private final DefaultRedisScript<Long> rateLimitScript =
            new DefaultRedisScript<>(RATE_LIMIT_SCRIPT, Long.class);

    public boolean isAllowed(String ipAddress, String username) {
        String key = buildKey(ipAddress, username);

        Long attempts = redisTemplate.execute(
                rateLimitScript,
                List.of(key),
                String.valueOf(WINDOW.getSeconds())
        );

        return attempts != null && attempts <= MAX_ATTEMPTS;
    }

    public void reset(String ipAddress, String username) {
        redisTemplate.delete(buildKey(ipAddress, username));
    }

    private String buildKey(String ipAddress, String username) {
        String identifier = String.valueOf(ipAddress) + ":" + String.valueOf(username);
        return KEY_PREFIX + sha256(identifier);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available", exception);
        }
    }
}
