package com.zaalima.iam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
public class ConsentController {

    private static final Map<String, String> SCOPE_DESCRIPTIONS;

    static {
        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put("openid", "Verify your identity.");
        descriptions.put("profile", "Access your basic profile information.");
        descriptions.put("email", "Access your email address.");
        descriptions.put("read", "Read access to your account data.");
        descriptions.put("write", "Modify access to your account data.");
        SCOPE_DESCRIPTIONS = Collections.unmodifiableMap(descriptions);
    }

    @GetMapping("/oauth2/consent")
    public String consent(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            Principal principal,
            Model model) {

        Set<String> scopesToApprove;
        if (StringUtils.hasText(scope)) {
            // Support both standard OAuth2 space-delimited and fallback comma-delimited scopes
            scopesToApprove = Arrays.stream(scope.split("[\\s,]+"))
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        } else {
            scopesToApprove = Collections.emptySet();
        }

        Map<String, String> scopesWithDescriptions = new LinkedHashMap<>();
        for (String s : scopesToApprove) {
            scopesWithDescriptions.put(s, SCOPE_DESCRIPTIONS.getOrDefault(s, "Access " + s));
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApprove);
        model.addAttribute("scopesWithDescriptions", scopesWithDescriptions);
        model.addAttribute("principalName", principal != null ? principal.getName() : "");

        return "consent";
    }
}
