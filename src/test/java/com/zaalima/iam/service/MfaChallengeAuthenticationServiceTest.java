package com.zaalima.iam.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaChallengeAuthenticationServiceTest {

    @Mock
    private MfaChallengeService mfaChallengeService;

    @Mock
    private MfaService mfaService;

    @InjectMocks
    private MfaChallengeAuthenticationService service;

    @Test
    void verifyChallengeShouldReturnFalseWhenChallengeIsMissing() {

        when(mfaChallengeService.hasValidChallenge("testuser"))
                .thenReturn(false);

        assertFalse(
                service.verifyChallenge("testuser", "123456")
        );

        verify(mfaService, never())
                .verifyCode("testuser", "123456");
    }

    @Test
    void verifyChallengeShouldReturnFalseWhenTotpIsInvalid() {

        when(mfaChallengeService.hasValidChallenge("testuser"))
                .thenReturn(true);

        when(mfaService.verifyCode("testuser", "123456"))
                .thenReturn(false);

        assertFalse(
                service.verifyChallenge("testuser", "123456")
        );

        verify(mfaChallengeService, never())
                .removeChallenge("testuser");
    }

    @Test
    void verifyChallengeShouldReturnTrueAndRemoveChallengeWhenTotpIsValid() {

        when(mfaChallengeService.hasValidChallenge("testuser"))
                .thenReturn(true);

        when(mfaService.verifyCode("testuser", "123456"))
                .thenReturn(true);

        assertTrue(
                service.verifyChallenge("testuser", "123456")
        );

        verify(mfaChallengeService)
                .removeChallenge("testuser");
    }
    @Test
    void successfulChallengeShouldNotBeReusable() {
        MfaChallengeService realChallengeService = new MfaChallengeService();
        MfaService mockMfaService = mock(MfaService.class);
        MfaChallengeAuthenticationService realService =
                new MfaChallengeAuthenticationService(realChallengeService, mockMfaService);

        realChallengeService.createChallenge("testuser");
        when(mockMfaService.verifyCode("testuser", "123456")).thenReturn(true);

        assertTrue(realService.verifyChallenge("testuser", "123456"));
        assertFalse(realService.verifyChallenge("testuser", "123456"));

        verify(mockMfaService, times(1)).verifyCode("testuser", "123456");
    }
}
