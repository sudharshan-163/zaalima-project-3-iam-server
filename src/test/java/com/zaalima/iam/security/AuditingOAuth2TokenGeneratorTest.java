package com.zaalima.iam.security;

import com.zaalima.iam.service.AuditLogService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditingOAuth2TokenGeneratorTest {

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private OAuth2TokenGenerator<org.springframework.security.oauth2.core.OAuth2Token> delegate;

    @Mock
    private OAuth2TokenContext context;

    @Mock
    private Authentication principal;

    @InjectMocks
    private AuditingOAuth2TokenGenerator tokenGenerator;

    @Test
    void generate_shouldAuditSuccessfulAccessTokenGeneration() {
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "test-access-token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Set.of("openid")
        );

        when(delegate.generate(context)).thenReturn(token);
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("testuser");
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS);

        OAuth2AccessToken result = (OAuth2AccessToken) tokenGenerator.generate(context);

        assertSame(token, result);
        verify(auditLogService).logSuccess(
                "testuser",
                "TOKEN_GENERATED",
                "OAuth2 token generated successfully. Token type: access_token, grant type: client_credentials"
        );
    }

    @Test
    void generate_shouldAuditRefreshTokenGeneration() {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "test-refresh-token",
                Instant.now(),
                Instant.now().plusSeconds(3600)
        );

        when(delegate.generate(context)).thenReturn(refreshToken);
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("testuser");
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);

        org.springframework.security.oauth2.core.OAuth2Token result = tokenGenerator.generate(context);

        assertSame(refreshToken, result);
        verify(auditLogService).logSuccess(
                "testuser",
                "TOKEN_GENERATED",
                "OAuth2 token generated successfully. Token type: refresh_token, grant type: authorization_code"
        );
    }

    @Test
    void generate_shouldHandleNullTokenTypeAndGrantTypeGracefully() {
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "token-without-types",
                Instant.now(),
                Instant.now().plusSeconds(300)
        );

        when(delegate.generate(context)).thenReturn(token);
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("testuser");
        when(context.getTokenType()).thenReturn(null);
        when(context.getAuthorizationGrantType()).thenReturn(null);

        org.springframework.security.oauth2.core.OAuth2Token result = tokenGenerator.generate(context);

        assertSame(token, result);
        verify(auditLogService).logSuccess(
                "testuser",
                "TOKEN_GENERATED",
                "OAuth2 token generated successfully. Token type: unknown, grant type: unknown"
        );
    }

    @Test
    void generate_shouldNotAuditWhenDelegateReturnsNull() {
        when(delegate.generate(context)).thenReturn(null);

        org.springframework.security.oauth2.core.OAuth2Token result = tokenGenerator.generate(context);

        assertNull(result);
        verifyNoInteractions(auditLogService);
    }
}
