package com.zaalima.iam.security;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.InvalidPasswordResetTokenException;
import com.zaalima.iam.repository.AuditLogRepository;
import com.zaalima.iam.repository.PasswordResetTokenRepository;
import com.zaalima.iam.repository.UserRepository;
import com.zaalima.iam.service.AuditLogService;
import com.zaalima.iam.service.MfaChallengeAuthenticationService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import com.zaalima.iam.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest
class SecurityAuditEventIntegrationTest {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuthenticationAuditListener authenticationAuditListener;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MfaChallengeAuthenticationService mfaChallengeAuthenticationService;

    @Autowired
    private MfaPendingAuthenticationService mfaPendingAuthenticationService;

    private final List<String> createdUsernames = new ArrayList<>();

    @BeforeEach
    void setUp() {
        cleanUpData();
    }

    @AfterEach
    void tearDown() {
        cleanUpData();
    }

    private void cleanUpData() {
        auditLogRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        for (String uname : createdUsernames) {
            userRepository.findByUsername(uname).ifPresent(userRepository::delete);
        }
        createdUsernames.clear();
    }

    private String randomUser() {
        String name = "audit_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        createdUsernames.add(name);
        return name;
    }

    private String randomEmail() {
        return "audit_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10) + "@example.com";
    }

    @Nested
    @DisplayName("AuthenticationAuditListener Audit Events")
    class AuthenticationAuditTests {

        @Test
        @DisplayName("Should persist LOGIN_SUCCESS audit log when authentication succeeds for non-MFA user")
        void shouldPersistLoginSuccessAuditLog() {
            String username = randomUser();
            Authentication auth = new UsernamePasswordAuthenticationToken(username, "secret123");

            authenticationAuditListener.onAuthenticationSuccess(new AuthenticationSuccessEvent(auth));

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("LOGIN_SUCCESS");
            assertThat(log.isSuccess()).isTrue();
            assertThat(log.getUsername()).isEqualTo(username);
            assertThat(log.getTimestamp()).isNotNull();
            assertThat(log.getDescription()).isEqualTo("User authentication completed successfully");
            assertThat(log.getDescription()).doesNotContain("secret123");
        }

        @Test
        @DisplayName("Should persist LOGIN_FAILED audit log on bad credentials failure")
        void shouldPersistLoginFailedAuditLog() {
            String username = randomUser();
            Authentication auth = new UsernamePasswordAuthenticationToken(username, "wrong_secret");

            authenticationAuditListener.onAuthenticationFailure(
                    new AuthenticationFailureBadCredentialsEvent(auth, new BadCredentialsException("Bad credentials"))
            );

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("LOGIN_FAILED");
            assertThat(log.isSuccess()).isFalse();
            assertThat(log.getUsername()).isEqualTo(username);
            assertThat(log.getTimestamp()).isNotNull();
            assertThat(log.getDescription()).isEqualTo("User authentication failed because the credentials were invalid");
            assertThat(log.getDescription()).doesNotContain("wrong_secret");
        }
    }

    @Nested
    @DisplayName("AuditingOAuth2TokenGenerator Audit Events")
    class TokenGeneratorAuditTests {

        @Test
        @DisplayName("Should persist TOKEN_GENERATED audit log without exposing raw token string")
        void shouldPersistTokenGeneratedAuditLogWithoutTokenExposure() {
            String username = randomUser();
            @SuppressWarnings("unchecked")
            OAuth2TokenGenerator<OAuth2Token> mockDelegate = mock(OAuth2TokenGenerator.class);
            OAuth2TokenContext mockContext = mock(OAuth2TokenContext.class);
            Authentication principal = mock(Authentication.class);

            String rawAccessToken = "eyJhbGciOiJSUzI1NiJ9.super-sensitive-token-payload";
            OAuth2AccessToken token = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    rawAccessToken,
                    Instant.now(),
                    Instant.now().plusSeconds(300),
                    Set.of("read", "write")
            );

            when(mockDelegate.generate(mockContext)).thenReturn(token);
            when(mockContext.getPrincipal()).thenReturn(principal);
            when(principal.getName()).thenReturn(username);
            when(mockContext.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
            when(mockContext.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);

            AuditingOAuth2TokenGenerator generator = new AuditingOAuth2TokenGenerator(auditLogService, mockDelegate);
            OAuth2Token generated = generator.generate(mockContext);

            assertThat(generated).isNotNull();

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("TOKEN_GENERATED");
            assertThat(log.isSuccess()).isTrue();
            assertThat(log.getUsername()).isEqualTo(username);
            assertThat(log.getTimestamp()).isNotNull();
            assertThat(log.getDescription())
                    .contains("Token type: access_token")
                    .contains("grant type: authorization_code")
                    .doesNotContain(rawAccessToken);
        }
    }

    @Nested
    @DisplayName("MfaAuthenticationController Audit Events")
    class MfaAuthenticationAuditTests {

        @Test
        @DisplayName("Should persist LOGIN_FAILED_MFA when MFA verification fails without exposing OTP code")
        void shouldPersistMfaFailureWithoutExposingOtp() {
            String username = randomUser();
            com.zaalima.iam.controller.MfaAuthenticationController controller =
                    new com.zaalima.iam.controller.MfaAuthenticationController(
                            mfaChallengeAuthenticationService,
                            mfaPendingAuthenticationService,
                            auditLogService
                    );

            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpSession session = new MockHttpSession();
            session.setAttribute("MFA_USERNAME", username);
            request.setSession(session);

            Authentication pendingAuth = new UsernamePasswordAuthenticationToken(username, null);
            mfaPendingAuthenticationService.store(username, pendingAuth);

            String sensitiveOtpCode = "987654";
            controller.verifyMfa(sensitiveOtpCode, request, new RedirectAttributesModelMap());

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("LOGIN_FAILED_MFA");
            assertThat(log.isSuccess()).isFalse();
            assertThat(log.getUsername()).isEqualTo(username);
            assertThat(log.getTimestamp()).isNotNull();
            assertThat(log.getDescription()).isEqualTo("User authentication failed because MFA verification was invalid or expired");
            assertThat(log.getDescription()).doesNotContain(sensitiveOtpCode);
        }
    }

    @Nested
    @DisplayName("UserService Audit Events")
    class UserServiceAuditTests {

        @Test
        @DisplayName("Should persist USER_REGISTERED audit log on user creation without exposing password")
        void shouldPersistUserRegisteredWithoutPasswordExposure() {
            String username = randomUser();
            String email = randomEmail();
            UserRegistrationRequest request = new UserRegistrationRequest();
            request.setUsername(username);
            request.setEmail(email);
            request.setPassword("P@ssw0rdSecure!999");

            userService.registerUser(request);

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("USER_REGISTERED");
            assertThat(log.isSuccess()).isTrue();
            assertThat(log.getUsername()).isEqualTo(username);
            assertThat(log.getTimestamp()).isNotNull();
            assertThat(log.getDescription()).isEqualTo("User registration completed successfully");
            assertThat(log.getDescription()).doesNotContain("P@ssw0rdSecure!999");
        }

        @Test
        @DisplayName("Should persist REGISTRATION_FAILED_DUPLICATE_USERNAME audit log on conflict")
        void shouldPersistDuplicateUsernameFailure() {
            String existingUsername = randomUser();
            User existing = new User();
            existing.setUsername(existingUsername);
            existing.setEmail(randomEmail());
            existing.setPassword(passwordEncoder.encode("Secret123"));
            existing.setEnabled(true);
            userRepository.save(existing);

            UserRegistrationRequest duplicateRequest = new UserRegistrationRequest();
            duplicateRequest.setUsername(existingUsername);
            duplicateRequest.setEmail(randomEmail());
            duplicateRequest.setPassword("NewPassword456");

            assertThrows(DuplicateUsernameException.class, () -> userService.registerUser(duplicateRequest));

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(existingUsername);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("REGISTRATION_FAILED_DUPLICATE_USERNAME");
            assertThat(log.isSuccess()).isFalse();
            assertThat(log.getDescription()).doesNotContain("NewPassword456");
        }

        @Test
        @DisplayName("Should persist REGISTRATION_FAILED_DUPLICATE_EMAIL audit log on conflict")
        void shouldPersistDuplicateEmailFailure() {
            String firstUsername = randomUser();
            String secondUsername = randomUser();
            String sharedEmail = randomEmail();

            User existing = new User();
            existing.setUsername(firstUsername);
            existing.setEmail(sharedEmail);
            existing.setPassword(passwordEncoder.encode("Secret123"));
            existing.setEnabled(true);
            userRepository.save(existing);

            UserRegistrationRequest duplicateRequest = new UserRegistrationRequest();
            duplicateRequest.setUsername(secondUsername);
            duplicateRequest.setEmail(sharedEmail);
            duplicateRequest.setPassword("NewPassword789");

            assertThrows(DuplicateEmailException.class, () -> userService.registerUser(duplicateRequest));

            List<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(secondUsername);
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.getEventType()).isEqualTo("REGISTRATION_FAILED_DUPLICATE_EMAIL");
            assertThat(log.isSuccess()).isFalse();
            assertThat(log.getDescription()).doesNotContain("NewPassword789");
        }

        @Test
        @DisplayName("Should persist PASSWORD_RESET_REQUESTED and PASSWORD_RESET_SUCCESS without sensitive tokens")
        void shouldPersistPasswordResetLifecycleWithoutSensitiveData() {
            String targetUsername = randomUser();
            String targetEmail = randomEmail();

            User user = new User();
            user.setUsername(targetUsername);
            user.setEmail(targetEmail);
            user.setPassword(passwordEncoder.encode("OldPassword123"));
            user.setEnabled(true);
            userRepository.save(user);

            ForgotPasswordRequest forgotReq = new ForgotPasswordRequest();
            forgotReq.setEmail(targetEmail);
            String rawToken = userService.createPasswordResetToken(forgotReq);

            assertThat(rawToken).isNotNull();

            List<AuditLog> reqLogs = auditLogRepository.findByEventTypeOrderByTimestampDesc("PASSWORD_RESET_REQUESTED");
            assertThat(reqLogs).isNotEmpty();
            AuditLog reqLog = reqLogs.get(0);
            assertThat(reqLog.getUsername()).isEqualTo(targetUsername);
            assertThat(reqLog.isSuccess()).isTrue();
            assertThat(reqLog.getDescription()).isEqualTo("Password reset requested");
            assertThat(reqLog.getDescription()).doesNotContain(rawToken);

            String newPassword = "BrandNewPassword2026!";
            ResetPasswordRequest resetReq = new ResetPasswordRequest();
            resetReq.setToken(rawToken);
            resetReq.setPassword(newPassword);

            userService.resetPassword(resetReq);

            List<AuditLog> successLogs = auditLogRepository.findByEventTypeOrderByTimestampDesc("PASSWORD_RESET_SUCCESS");
            assertThat(successLogs).isNotEmpty();
            AuditLog successLog = successLogs.get(0);
            assertThat(successLog.getUsername()).isEqualTo(targetUsername);
            assertThat(successLog.isSuccess()).isTrue();
            assertThat(successLog.getDescription()).isEqualTo("Password reset completed successfully");
            assertThat(successLog.getDescription())
                    .doesNotContain(rawToken)
                    .doesNotContain(newPassword);
        }

        @Test
        @DisplayName("Should persist PASSWORD_RESET_INVALID_TOKEN when reset token is unrecognized")
        void shouldPersistPasswordResetInvalidToken() {
            String fakeToken = "completely-invalid-token-uuid-" + UUID.randomUUID();
            ResetPasswordRequest invalidReq = new ResetPasswordRequest();
            invalidReq.setToken(fakeToken);
            invalidReq.setPassword("SomePassword123");

            assertThrows(InvalidPasswordResetTokenException.class, () -> userService.resetPassword(invalidReq));

            List<AuditLog> logs = auditLogRepository.findByEventTypeOrderByTimestampDesc("PASSWORD_RESET_INVALID_TOKEN");
            assertThat(logs).hasSize(1);

            AuditLog log = logs.get(0);
            assertThat(log.isSuccess()).isFalse();
            assertThat(log.getDescription()).isEqualTo("Password reset failed because the token is invalid");
            assertThat(log.getDescription())
                    .doesNotContain(fakeToken)
                    .doesNotContain("SomePassword123");
        }
    }
}