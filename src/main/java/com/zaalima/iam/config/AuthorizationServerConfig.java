package com.zaalima.iam.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import com.zaalima.iam.service.OidcUserInfoService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OidcUserInfoService oidcUserInfoService) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        RequestMatcher endpointsMatcher =
                authorizationServerConfigurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .with(
                        authorizationServerConfigurer,
                        authorizationServer -> authorizationServer
                                .authorizationEndpoint(authorizationEndpoint ->
                                        authorizationEndpoint.consentPage("/oauth2/consent")
                                )
                                .oidc(oidc -> oidc
                                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                                .userInfoMapper(context -> new OidcUserInfo(
                                                        oidcUserInfoService.getUserInfo(
                                                                context.getAuthorization().getPrincipalName()
                                                        )
                                                ))
                                        ))
                )
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated())
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                endpointsMatcher
                        ))
                .oauth2ResourceServer(resourceServer ->
                        resourceServer.jwt(withDefaults()));

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {

        KeyPair keyPair = generateRsaKey();

        RSAPublicKey publicKey =
                (RSAPublicKey) keyPair.getPublic();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(
                new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(
            JWKSource<SecurityContext> jwkSource) {

        return OAuth2AuthorizationServerConfiguration
                .jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {

        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8085")
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder) {

        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("iam-test-client")
                .clientSecret(
                        passwordEncoder.encode("iam-test-secret"))
                .clientAuthenticationMethod(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(
                        AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(
                        AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(
                        "http://localhost:8085/oauth2/callback")
                .scope("openid")
                .scope("profile")
                .clientSettings(
                        ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .build())
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    private KeyPair generateRsaKey() {

        try {
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(2048);

            return keyPairGenerator.generateKeyPair();

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to generate RSA key pair",
                    exception);
        }
    }
}
