package com.zaalima.iam.service;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.*;

class MfaPendingAuthenticationServiceTest {

    @Test
    void storeShouldSaveAuthentication() {

        MfaPendingAuthenticationService service =
                new MfaPendingAuthenticationService();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        null
                );

        service.store("testuser", authentication);

        assertSame(
                authentication,
                service.get("testuser")
        );
    }

    @Test
    void getShouldReturnNullForUnknownUser() {

        MfaPendingAuthenticationService service =
                new MfaPendingAuthenticationService();

        assertNull(
                service.get("unknownuser")
        );
    }

    @Test
    void removeShouldDeletePendingAuthentication() {

        MfaPendingAuthenticationService service =
                new MfaPendingAuthenticationService();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        null
                );

        service.store("testuser", authentication);
        service.remove("testuser");

        assertNull(
                service.get("testuser")
        );
    }
}
