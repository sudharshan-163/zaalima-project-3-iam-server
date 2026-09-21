package com.zaalima.iam.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.List;

import static org.mockito.Mockito.*;

class JwtTokenCustomizerTest {

    @Test
    void jwtTokenCustomizer_shouldAddRolesAndAuthorities() {

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        OAuth2TokenType tokenType = mock(OAuth2TokenType.class);
        JwtClaimsSet.Builder claims = mock(JwtClaimsSet.Builder.class);

        when(tokenType.getValue()).thenReturn("access_token");
        when(context.getTokenType()).thenReturn(tokenType);

        var authentication =
                new UsernamePasswordAuthenticationToken(
                        "oauthday6",
                        null,
                        List.of(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("READ_PROFILE")
                        ));

        when(context.getPrincipal()).thenReturn(authentication);
        when(context.getClaims()).thenReturn(claims);

        when(claims.claim(anyString(), any()))
                .thenReturn(claims);

        JwtTokenCustomizerConfig config =
                new JwtTokenCustomizerConfig();

        config.jwtTokenCustomizer().customize(context);

        verify(claims).claim(
                "roles",
                List.of("USER")
        );

        verify(claims).claim(
                "authorities",
                List.of("ROLE_USER", "READ_PROFILE")
        );
    }

    @Test
    void jwtTokenCustomizer_shouldIgnoreNonAccessTokens() {

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        OAuth2TokenType tokenType = mock(OAuth2TokenType.class);

        when(tokenType.getValue()).thenReturn("id_token");
        when(context.getTokenType()).thenReturn(tokenType);

        JwtTokenCustomizerConfig config =
                new JwtTokenCustomizerConfig();

        config.jwtTokenCustomizer().customize(context);

        verify(context, never()).getPrincipal();
        verify(context, never()).getClaims();
    }
}
