package com.zaalima.iam.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Instant;

@Getter
@RequiredArgsConstructor
public class MfaChallenge {

    private final String username;
    private final Instant createdAt;

    public boolean isExpired(long maxAgeSeconds) {
        return createdAt.plusSeconds(maxAgeSeconds)
                .isBefore(Instant.now());
    }
}
