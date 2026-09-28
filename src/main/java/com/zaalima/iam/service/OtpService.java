package com.zaalima.iam.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class OtpService {

    private static final String KEY_PREFIX = "iam:otp:";
    private static final int OTP_LENGTH = 6;
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public String generateAndStoreOtp(String identifier) {
        return generateAndStoreOtp(identifier, DEFAULT_TTL);
    }

    public String generateAndStoreOtp(String identifier, Duration ttl) {
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Identifier must not be blank");
        }

        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("OTP TTL must be positive");
        }

        int number = secureRandom.nextInt(1_000_000);
        String otp = String.format("%0" + OTP_LENGTH + "d", number);

        redisTemplate.opsForValue().set(
                KEY_PREFIX + identifier,
                otp,
                ttl
        );

        return otp;
    }

    public boolean verifyOtp(String identifier, String otp) {
        if (identifier == null || identifier.isBlank() || otp == null || otp.isBlank()) {
            return false;
        }

        String redisKey = KEY_PREFIX + identifier;
        String storedOtp = redisTemplate.opsForValue().get(redisKey);

        if (storedOtp == null) {
            return false;
        }

        if (storedOtp.equals(otp.trim())) {
            redisTemplate.delete(redisKey);
            return true;
        }

        return false;
    }

    public void invalidateOtp(String identifier) {
        if (identifier != null && !identifier.isBlank()) {
            redisTemplate.delete(KEY_PREFIX + identifier);
        }
    }

    public boolean hasPendingOtp(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + identifier));
    }
}