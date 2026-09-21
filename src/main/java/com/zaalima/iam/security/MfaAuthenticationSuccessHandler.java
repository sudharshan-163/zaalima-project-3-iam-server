package com.zaalima.iam.security;

import com.zaalima.iam.service.MfaAuthenticationService;
import com.zaalima.iam.service.MfaChallengeService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class MfaAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private final MfaAuthenticationService mfaAuthenticationService;
    private final MfaChallengeService mfaChallengeService;
    private final MfaPendingAuthenticationService
            mfaPendingAuthenticationService;

    private final SavedRequestAwareAuthenticationSuccessHandler
            defaultSuccessHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        String username = authentication.getName();

        if (!mfaAuthenticationService.isMfaEnabled(username)) {

            defaultSuccessHandler.onAuthenticationSuccess(
                    request,
                    response,
                    authentication
            );

            return;
        }

        mfaPendingAuthenticationService.store(
                username,
                authentication
        );

        mfaChallengeService.createChallenge(username);

        request.getSession().setAttribute(
                "MFA_USERNAME",
                username
        );

        SecurityContextHolder.clearContext();

        response.sendRedirect("/mfa");
    }
}
