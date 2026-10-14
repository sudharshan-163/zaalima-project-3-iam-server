package com.zaalima.iam.security;

import com.zaalima.iam.service.MfaAuthenticationService;
import com.zaalima.iam.service.MfaChallengeService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaAuthenticationSuccessHandlerTest {

    @Mock
    private MfaAuthenticationService mfaAuthenticationService;

    @Mock
    private MfaChallengeService mfaChallengeService;

    @Mock
    private MfaPendingAuthenticationService mfaPendingAuthenticationService;

    @InjectMocks
    private MfaAuthenticationSuccessHandler handler;

    @Test
    void onAuthenticationSuccess_shouldRedirectToMfaWhenMfaIsEnabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken("testuser", "password");

        when(mfaAuthenticationService.isMfaEnabled("testuser")).thenReturn(true);

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(mfaPendingAuthenticationService).store("testuser", authentication);
        verify(mfaChallengeService).createChallenge("testuser");
        assertEquals("testuser", request.getSession().getAttribute("MFA_USERNAME"));
        assertEquals("/mfa", response.getRedirectedUrl());
    }

    @Test
    void onAuthenticationSuccess_shouldUseDefaultTargetWhenMfaDisabledAndNoSavedRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken("testuser", "password");

        when(mfaAuthenticationService.isMfaEnabled("testuser")).thenReturn(false);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertEquals("/api/users/me", response.getRedirectedUrl());
        verifyNoInteractions(mfaChallengeService);
    }
}