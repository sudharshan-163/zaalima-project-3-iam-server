package com.zaalima.iam.security;

import com.zaalima.iam.service.TokenRevocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class RedisJwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private final TokenRevocationService tokenRevocationService;

    private final JwtAuthenticationConverter delegate =
            createJwtAuthenticationConverter();

    private static JwtAuthenticationConverter createJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter =
                new JwtGrantedAuthoritiesConverter();

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Set<org.springframework.security.core.GrantedAuthority> authorities = new LinkedHashSet<>();

            Collection<org.springframework.security.core.GrantedAuthority> defaults =
                    defaultAuthoritiesConverter.convert(jwt);

            if (defaults != null) {
                defaults.forEach(authority ->
                        authorities.add(new SimpleGrantedAuthority(authority.getAuthority())));
            }

            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                roles.stream()
                        .filter(role -> role != null && !role.isBlank())
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            List<String> tokenAuthorities = jwt.getClaimAsStringList("authorities");
            if (tokenAuthorities != null) {
                tokenAuthorities.stream()
                        .filter(authority -> authority != null && !authority.isBlank())
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            return authorities;
        });

        return converter;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {

        String jti = jwt.getId();

        if (jti != null && tokenRevocationService.isRevoked(jti)) {
            throw new InvalidBearerTokenException(
                    "Access token has been revoked");
        }

        return delegate.convert(jwt);
    }
}
