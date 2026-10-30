package com.zaalima.iam.controller;

import com.zaalima.iam.service.MfaChallengeAuthenticationService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import com.zaalima.iam.service.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class MfaAuthenticationController {

    private final MfaChallengeAuthenticationService
            mfaChallengeAuthenticationService;

    private final MfaPendingAuthenticationService
            mfaPendingAuthenticationService;

    private final AuditLogService auditLogService;

    private final RequestCache requestCache = new HttpSessionRequestCache();

    @GetMapping("/mfa")
    public String showMfaPage() {
        return "mfa";
    }

    @PostMapping("/mfa")
    public String verifyMfa(
            @RequestParam String code,
            HttpServletRequest request,
            HttpServletResponse response,
            RedirectAttributes redirectAttributes) {

        Authentication pendingAuthentication =
                getPendingAuthentication(request);

        if (pendingAuthentication == null) {
            redirectAttributes.addFlashAttribute(
                    "error",
                    "MFA session expired. Please login again."
            );
            return "redirect:/login.html";
        }

        String username = pendingAuthentication.getName();

        boolean valid =
                mfaChallengeAuthenticationService
                        .verifyChallenge(username, code);

        if (!valid) {
            auditLogService.logFailure(
                    username,
                    "LOGIN_FAILED_MFA",
                    "User authentication failed because MFA verification was invalid or expired"
            );
            redirectAttributes.addFlashAttribute(
                    "error",
                    "Invalid or expired MFA code."
            );
            return "redirect:/mfa?error=true";
        }

        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(pendingAuthentication);

        SecurityContextHolder.setContext(context);

        new HttpSessionSecurityContextRepository()
                .saveContext(
                        context,
                        request,
                        response
                );

        mfaPendingAuthenticationService.remove(username);

        auditLogService.logSuccess(
                username,
                "LOGIN_SUCCESS",
                "User authentication completed successfully after MFA verification"
        );

        if (response != null) {
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            if (savedRequest != null) {
                String targetUrl = savedRequest.getRedirectUrl();
                requestCache.removeRequest(request, response);
                return "redirect:" + targetUrl;
            }
        }

        return "redirect:/dashboard.html";
    }

    public String verifyMfa(
            String code,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {
        return verifyMfa(code, request, null, redirectAttributes);
    }

    private Authentication getPendingAuthentication(
            HttpServletRequest request) {

        Object username =
                request.getSession().getAttribute("MFA_USERNAME");

        if (username == null) {
            return null;
        }

        return mfaPendingAuthenticationService
                .get(username.toString());
    }
}



