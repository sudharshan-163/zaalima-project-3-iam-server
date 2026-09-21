package com.zaalima.iam.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class MfaChallengeService {

    private static final long CHALLENGE_EXPIRY_SECONDS = 300;

    private final Map<String, MfaChallenge> challenges =
            new ConcurrentHashMap<>();

    public void createChallenge(String username) {

        challenges.put(
                username,
                new MfaChallenge(username, Instant.now())
        );
    }

    public boolean hasValidChallenge(String username) {

        MfaChallenge challenge = challenges.get(username);

        if (challenge == null) {
            return false;
        }

        if (challenge.isExpired(CHALLENGE_EXPIRY_SECONDS)) {
            challenges.remove(username);
            return false;
        }

        return true;
    }

    public void removeChallenge(String username) {
        challenges.remove(username);
    }
}
