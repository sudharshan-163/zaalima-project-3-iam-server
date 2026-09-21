package com.zaalima.iam.controller;

import com.zaalima.iam.service.MfaChallengeAuthenticationService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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

    @GetMapping("/mfa")
    public String showMfaPage() {
        return "mfa";
    }

    @PostMapping("/mfa")
    public String verifyMfa(
            @RequestParam String code,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        Authentication pendingAuthentication =
                getPendingAuthentication(request);

        if (pendingAuthentication == null) {
            redirectAttributes.addFlashAttribute(
                    "error",
                    "MFA session expired. Please login again."
            );
            return "redirect:/login";
        }

        String username = pendingAuthentication.getName();

        boolean valid =
                mfaChallengeAuthenticationService
                        .verifyChallenge(username, code);

        if (!valid) {
            redirectAttributes.addFlashAttribute(
                    "error",
                    "Invalid or expired MFA code."
            );
            return "redirect:/mfa";
        }

        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(pendingAuthentication);

        SecurityContextHolder.setContext(context);

        new HttpSessionSecurityContextRepository()
                .saveContext(
                        context,
                        request,
                        null
                );

        mfaPendingAuthenticationService.remove(username);

        return "redirect:/";
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
