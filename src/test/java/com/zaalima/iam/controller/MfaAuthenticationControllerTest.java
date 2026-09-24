package com.zaalima.iam.controller;

import com.zaalima.iam.service.AuditLogService;
import com.zaalima.iam.service.MfaChallengeAuthenticationService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaAuthenticationControllerTest {

    @Mock
    private MfaChallengeAuthenticationService
            mfaChallengeAuthenticationService;

    @Mock
    private MfaPendingAuthenticationService
            mfaPendingAuthenticationService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpSession session;

    @Mock
    private RedirectAttributes redirectAttributes;

    @InjectMocks
    private MfaAuthenticationController controller;

    @Test
    void verifyMfa_shouldAuditFailureWhenCodeIsInvalid() {

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        null
                );

        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("MFA_USERNAME"))
                .thenReturn("testuser");

        when(mfaPendingAuthenticationService.get("testuser"))
                .thenReturn(authentication);

        when(mfaChallengeAuthenticationService
                .verifyChallenge("testuser", "123456"))
                .thenReturn(false);

        String result = controller.verifyMfa(
                "123456",
                request,
                redirectAttributes
        );

        assertEquals("redirect:/mfa", result);

        verify(auditLogService).logFailure(
                "testuser",
                "LOGIN_FAILED_MFA",
                "User authentication failed because MFA verification was invalid or expired"
        );

        verify(auditLogService, never()).logSuccess(
                anyString(),
                anyString(),
                anyString()
        );
    }
}

