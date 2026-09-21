package com.zaalima.iam.service;

import com.zaalima.iam.entity.MfaCredential;
import com.zaalima.iam.repository.MfaCredentialRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaAuthenticationServiceTest {

    @Mock
    private MfaCredentialRepository mfaCredentialRepository;

    @InjectMocks
    private MfaAuthenticationService mfaAuthenticationService;

    @Test
    void isMfaEnabledShouldReturnTrueWhenMfaIsEnabled() {

        MfaCredential credential = new MfaCredential();
        credential.setEnabled(true);

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.of(credential));

        assertTrue(
                mfaAuthenticationService.isMfaEnabled("testuser")
        );
    }

    @Test
    void isMfaEnabledShouldReturnFalseWhenMfaIsDisabled() {

        MfaCredential credential = new MfaCredential();
        credential.setEnabled(false);

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.of(credential));

        assertFalse(
                mfaAuthenticationService.isMfaEnabled("testuser")
        );
    }

    @Test
    void isMfaEnabledShouldReturnFalseWhenMfaIsNotConfigured() {

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.empty());

        assertFalse(
                mfaAuthenticationService.isMfaEnabled("testuser")
        );
    }
}
