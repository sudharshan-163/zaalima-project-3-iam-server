package com.zaalima.iam.security;

import com.zaalima.iam.service.AuditLogService;
import com.zaalima.iam.service.MfaAuthenticationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationAuditListenerTest {

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private MfaAuthenticationService mfaAuthenticationService;

    @InjectMocks
    private AuthenticationAuditListener authenticationAuditListener;

    @Test
    void authenticationSuccess_shouldCreateLoginSuccessAudit() {

        var authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        "password"
                );

        when(mfaAuthenticationService.isMfaEnabled("testuser"))
                .thenReturn(false);

        authenticationAuditListener.onAuthenticationSuccess(
                new AuthenticationSuccessEvent(authentication)
        );

        verify(auditLogService).logSuccess(
                "testuser",
                "LOGIN_SUCCESS",
                "User authentication completed successfully"
        );
    }

    @Test
    void authenticationSuccess_withMfaEnabled_shouldNotCreateDuplicateAudit() {

        var authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        "password"
                );

        when(mfaAuthenticationService.isMfaEnabled("testuser"))
                .thenReturn(true);

        authenticationAuditListener.onAuthenticationSuccess(
                new AuthenticationSuccessEvent(authentication)
        );

        verifyNoInteractions(auditLogService);
    }

    @Test
    void authenticationFailure_shouldCreateLoginFailureAudit() {

        var authentication =
                new UsernamePasswordAuthenticationToken(
                        "testuser",
                        "wrong-password"
                );

        authenticationAuditListener.onAuthenticationFailure(
                new AuthenticationFailureBadCredentialsEvent(
                        authentication,
                        new BadCredentialsException("Bad credentials")
                )
        );

        verify(auditLogService).logFailure(
                "testuser",
                "LOGIN_FAILED",
                "User authentication failed because the credentials were invalid"
        );
    }
}

