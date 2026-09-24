package com.zaalima.iam.security;

import com.zaalima.iam.service.AuditLogService;
import com.zaalima.iam.service.MfaAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationAuditListener {

    private final AuditLogService auditLogService;
    private final MfaAuthenticationService mfaAuthenticationService;

    @EventListener
    public void onAuthenticationSuccess(
            AuthenticationSuccessEvent event) {

        String username = event.getAuthentication().getName();

        if (mfaAuthenticationService.isMfaEnabled(username)) {
            return;
        }

        auditLogService.logSuccess(
                username,
                "LOGIN_SUCCESS",
                "User authentication completed successfully"
        );
    }

    @EventListener
    public void onAuthenticationFailure(
            AuthenticationFailureBadCredentialsEvent event) {

        String username =
                event.getAuthentication().getName();

        auditLogService.logFailure(
                username,
                "LOGIN_FAILED",
                "User authentication failed because the credentials were invalid"
        );
    }
}
