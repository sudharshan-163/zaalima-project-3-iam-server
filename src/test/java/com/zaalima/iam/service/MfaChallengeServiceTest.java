package com.zaalima.iam.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MfaChallengeServiceTest {

    @Test
    void createChallengeShouldCreateValidChallenge() {

        MfaChallengeService service = new MfaChallengeService();

        service.createChallenge("testuser");

        assertTrue(service.hasValidChallenge("testuser"));
    }

    @Test
    void hasValidChallengeShouldReturnFalseForUnknownUser() {

        MfaChallengeService service = new MfaChallengeService();

        assertFalse(
                service.hasValidChallenge("unknownuser")
        );
    }

    @Test
    void removeChallengeShouldInvalidateChallenge() {

        MfaChallengeService service = new MfaChallengeService();

        service.createChallenge("testuser");
        service.removeChallenge("testuser");

        assertFalse(
                service.hasValidChallenge("testuser")
        );
    }
    @Test
    void expiredChallengeShouldBeDetected() {
        MfaChallenge challenge = new MfaChallenge(
                "testuser",
                java.time.Instant.now().minusSeconds(301)
        );

        assertTrue(challenge.isExpired(300));
    }
}
