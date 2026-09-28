package com.zaalima.iam.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OtpServiceTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOperations;
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        valueOperations = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        otpService = new OtpService(redisTemplate);
    }

    @Nested
    @DisplayName("Generation and Storage Tests")
    class GenerationTests {

        @Test
        @DisplayName("Should generate a 6-digit numeric OTP and store it in Redis with default 5-minute TTL")
        void generateAndStoreOtp_defaultTtl_success() {
            String identifier = "user@example.com";

            String otp = otpService.generateAndStoreOtp(identifier);

            assertNotNull(otp);
            assertEquals(6, otp.length());
            assertTrue(otp.matches("\\d{6}"), "OTP must contain exactly 6 digits");

            verify(valueOperations).set("iam:otp:" + identifier, otp, Duration.ofMinutes(5));
        }

        @Test
        @DisplayName("Should store OTP with custom TTL")
        void generateAndStoreOtp_customTtl_success() {
            String identifier = "+919876543210";
            Duration customTtl = Duration.ofMinutes(2);

            String otp = otpService.generateAndStoreOtp(identifier, customTtl);

            assertNotNull(otp);
            assertEquals(6, otp.length());
            assertTrue(otp.matches("\\d{6}"));

            verify(valueOperations).set("iam:otp:" + identifier, otp, customTtl);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when identifier is blank or null")
        void generateAndStoreOtp_invalidIdentifier_throwsException() {
            assertThrows(IllegalArgumentException.class, () -> otpService.generateAndStoreOtp(null));
            assertThrows(IllegalArgumentException.class, () -> otpService.generateAndStoreOtp("   "));
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when TTL is null, zero, or negative")
        void generateAndStoreOtp_invalidTtl_throwsException() {
            assertThrows(IllegalArgumentException.class, () -> otpService.generateAndStoreOtp("user1", null));
            assertThrows(IllegalArgumentException.class, () -> otpService.generateAndStoreOtp("user1", Duration.ZERO));
            assertThrows(IllegalArgumentException.class, () -> otpService.generateAndStoreOtp("user1", Duration.ofSeconds(-10)));
        }
    }

    @Nested
    @DisplayName("Verification and Single-Use Tests")
    class VerificationTests {

        @Test
        @DisplayName("Should return true and delete key when OTP is valid and matching (Single-use)")
        void verifyOtp_validOtp_returnsTrueAndDeletesKey() {
            String identifier = "user@example.com";
            String expectedOtp = "123456";

            when(valueOperations.get("iam:otp:" + identifier)).thenReturn(expectedOtp);

            boolean result = otpService.verifyOtp(identifier, expectedOtp);

            assertTrue(result);
            verify(redisTemplate).delete("iam:otp:" + identifier);
        }

        @Test
        @DisplayName("Should return false and not delete key when OTP does not match")
        void verifyOtp_incorrectOtp_returnsFalseAndPreservesKey() {
            String identifier = "user@example.com";

            when(valueOperations.get("iam:otp:" + identifier)).thenReturn("123456");

            boolean result = otpService.verifyOtp(identifier, "654321");

            assertFalse(result);
            verify(redisTemplate, never()).delete("iam:otp:" + identifier);
        }

        @Test
        @DisplayName("Should return false when OTP has expired or does not exist in Redis")
        void verifyOtp_expiredOrMissingOtp_returnsFalse() {
            String identifier = "user@example.com";

            when(valueOperations.get("iam:otp:" + identifier)).thenReturn(null);

            boolean result = otpService.verifyOtp(identifier, "123456");

            assertFalse(result);
            verify(redisTemplate, never()).delete(anyString());
        }

        @Test
        @DisplayName("Should return false when identifier or OTP is blank or null")
        void verifyOtp_nullOrBlankInputs_returnsFalse() {
            assertFalse(otpService.verifyOtp(null, "123456"));
            assertFalse(otpService.verifyOtp("   ", "123456"));
            assertFalse(otpService.verifyOtp("user@example.com", null));
            assertFalse(otpService.verifyOtp("user@example.com", "   "));

            verifyNoInteractions(valueOperations);
        }

        @Test
        @DisplayName("Should prevent replay attack by ensuring OTP cannot be verified twice")
        void verifyOtp_replayPrevention_secondAttemptFails() {
            String identifier = "user@example.com";
            String otp = "789012";

            when(valueOperations.get("iam:otp:" + identifier)).thenReturn(otp);
            boolean firstAttempt = otpService.verifyOtp(identifier, otp);
            assertTrue(firstAttempt);
            verify(redisTemplate).delete("iam:otp:" + identifier);

            when(valueOperations.get("iam:otp:" + identifier)).thenReturn(null);
            boolean secondAttempt = otpService.verifyOtp(identifier, otp);
            assertFalse(secondAttempt);
        }
    }

    @Nested
    @DisplayName("Invalidation and Status Tests")
    class InvalidationAndStatusTests {

        @Test
        @DisplayName("Should delete key when invalidateOtp is called with valid identifier")
        void invalidateOtp_validIdentifier_deletesKey() {
            String identifier = "user@example.com";

            otpService.invalidateOtp(identifier);

            verify(redisTemplate).delete("iam:otp:" + identifier);
        }

        @Test
        @DisplayName("Should do nothing when invalidateOtp is called with blank identifier")
        void invalidateOtp_blankIdentifier_doesNothing() {
            otpService.invalidateOtp("");
            otpService.invalidateOtp(null);

            verify(redisTemplate, never()).delete(anyString());
        }

        @Test
        @DisplayName("hasPendingOtp should return true when key exists in Redis")
        void hasPendingOtp_exists_returnsTrue() {
            String identifier = "user@example.com";
            when(redisTemplate.hasKey("iam:otp:" + identifier)).thenReturn(true);

            assertTrue(otpService.hasPendingOtp(identifier));
        }

        @Test
        @DisplayName("hasPendingOtp should return false when key does not exist or input is blank")
        void hasPendingOtp_missingOrBlank_returnsFalse() {
            String identifier = "user@example.com";
            when(redisTemplate.hasKey("iam:otp:" + identifier)).thenReturn(false);

            assertFalse(otpService.hasPendingOtp(identifier));
            assertFalse(otpService.hasPendingOtp("   "));
            assertFalse(otpService.hasPendingOtp(null));
        }
    }
}