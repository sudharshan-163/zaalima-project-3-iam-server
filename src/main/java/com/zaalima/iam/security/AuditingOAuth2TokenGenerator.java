package com.zaalima.iam.security;

import com.zaalima.iam.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

@RequiredArgsConstructor
public class AuditingOAuth2TokenGenerator
        implements OAuth2TokenGenerator<OAuth2Token> {

    private final AuditLogService auditLogService;
    private final OAuth2TokenGenerator<OAuth2Token> delegate;

    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {

        OAuth2Token token = delegate.generate(context);

        if (token == null) {
            return null;
        }

        String username = context.getPrincipal().getName();

        String tokenType =
                context.getTokenType() != null
                        ? context.getTokenType().getValue()
                        : "unknown";

        String grantType =
                context.getAuthorizationGrantType() != null
                        ? context.getAuthorizationGrantType().getValue()
                        : "unknown";

        auditLogService.logSuccess(
                username,
                "TOKEN_GENERATED",
                "OAuth2 token generated successfully. Token type: "
                        + tokenType
                        + ", grant type: "
                        + grantType
        );

        return token;
    }
}
