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
    private static final String IP_KEY_PREFIX = "iam:rate-limit:login-ip:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private static final String RATE_LIMIT_SCRIPT = """
            local accountCurrent = redis.call('INCR', KEYS[1])
            local ipCurrent = redis.call('INCR', KEYS[2])

            if accountCurrent == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end

            if ipCurrent == 1 then
                redis.call('EXPIRE', KEYS[2], ARGV[1])
            end

            if accountCurrent > tonumber(ARGV[2]) or ipCurrent > tonumber(ARGV[2]) then
                return 0
            end

            return 1
            """;

    private final StringRedisTemplate redisTemplate;

    private final DefaultRedisScript<Long> rateLimitScript =
            new DefaultRedisScript<>(RATE_LIMIT_SCRIPT, Long.class);

    public boolean isAllowed(String ipAddress, String username) {
        String accountKey = buildKey(ipAddress, username);
        String ipKey = buildIpKey(ipAddress);

        Long allowed = redisTemplate.execute(
                rateLimitScript,
                List.of(accountKey, ipKey),
                String.valueOf(WINDOW.getSeconds()),
                String.valueOf(MAX_ATTEMPTS)
        );

        return Long.valueOf(1L).equals(allowed);
    }

    public void reset(String ipAddress, String username) {
        redisTemplate.delete(buildKey(ipAddress, username));
        redisTemplate.delete(buildIpKey(ipAddress));
    }

    private String buildKey(String ipAddress, String username) {
        String identifier = String.valueOf(ipAddress) + ":" + String.valueOf(username);
        return KEY_PREFIX + sha256(identifier);
    }

    private String buildIpKey(String ipAddress) {
        return IP_KEY_PREFIX + sha256(String.valueOf(ipAddress));
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
