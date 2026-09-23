package com.zaalima.iam.security;

import com.zaalima.iam.service.TokenRevocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RedisJwtAuthenticationConverter
        implements org.springframework.core.convert.converter.Converter<
                Jwt,
                AbstractAuthenticationToken> {

    private final TokenRevocationService tokenRevocationService;

    private final JwtAuthenticationConverter delegate =
            new JwtAuthenticationConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {

        String jti = jwt.getId();

        if (jti != null &&
                tokenRevocationService.isRevoked(jti)) {

            throw new InvalidBearerTokenException(
                    "Access token has been revoked");
        }

        return delegate.convert(jwt);
    }
}
