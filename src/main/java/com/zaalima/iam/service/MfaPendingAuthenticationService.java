package com.zaalima.iam.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class MfaPendingAuthenticationService {

    private static final long PENDING_AUTH_EXPIRY_SECONDS = 300;

    private final Map<String, PendingAuthentication> pendingAuthentications =
            new ConcurrentHashMap<>();

    public void store(String username, Authentication authentication) {
        pendingAuthentications.put(
                username,
                new PendingAuthentication(authentication, Instant.now())
        );
    }

    public Authentication get(String username) {

        PendingAuthentication pending =
                pendingAuthentications.get(username);

        if (pending == null) {
            return null;
        }

        if (pending.isExpired()) {
            pendingAuthentications.remove(username);
            return null;
        }

        return pending.authentication();
    }

    public void remove(String username) {
        pendingAuthentications.remove(username);
    }

    private record PendingAuthentication(
            Authentication authentication,
            Instant createdAt
    ) {

        private boolean isExpired() {
            return createdAt
                    .plusSeconds(PENDING_AUTH_EXPIRY_SECONDS)
                    .isBefore(Instant.now());
        }
    }
}
