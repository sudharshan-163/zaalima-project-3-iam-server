package com.zaalima.iam.service;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.entity.PasswordResetToken;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.InvalidPasswordResetTokenException;
import com.zaalima.iam.repository.AuthorityRepository;
import com.zaalima.iam.repository.PasswordResetTokenRepository;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceAuditTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthorityRepository authorityRepository;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private UserService userService;

    private Role userRole;

    @BeforeEach
    void setUp() {
        userRole = new Role();
        userRole.setId(1L);
        userRole.setName("USER");
    }

    @Test
    void registerUser_shouldCreateSuccessAudit() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("audituser");
        request.setEmail("audit@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("audituser")).thenReturn(false);
        when(userRepository.existsByEmail("audit@example.com")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("Password123")).thenReturn("encoded-password");

        User savedUser = new User();
        savedUser.setId(10L);
        savedUser.setUsername("audituser");
        savedUser.setEmail("audit@example.com");
        savedUser.setPassword("encoded-password");
        savedUser.setEnabled(true);
        savedUser.getRoles().add(userRole);

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        userService.registerUser(request);

        verify(auditLogService).logSuccess(
            "audituser",
            "USER_REGISTERED",
            "User registration completed successfully"
        );
    }

    @Test
    void registerUser_duplicateUsername_shouldCreateFailureAudit() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("existinguser");
        request.setEmail("new@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        assertThrows(
            DuplicateUsernameException.class,
            () -> userService.registerUser(request)
        );

        verify(auditLogService).logFailure(
            "existinguser",
            "REGISTRATION_FAILED_DUPLICATE_USERNAME",
            "User registration failed because the username already exists"
        );
    }

    @Test
    void registerUser_duplicateEmail_shouldCreateFailureAudit() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("newuser");
        request.setEmail("existing@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        assertThrows(
            DuplicateEmailException.class,
            () -> userService.registerUser(request)
        );

        verify(auditLogService).logFailure(
            "newuser",
            "REGISTRATION_FAILED_DUPLICATE_EMAIL",
            "User registration failed because the email already exists"
        );
    }

    @Test
    void resetPassword_success_shouldCreateSuccessAuditWithoutPasswordOrToken() {

        User user = new User();
        user.setUsername("resetuser");

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken("secret-reset-token");
        resetToken.setUser(user);
        resetToken.setExpiresAt(Instant.now().plusSeconds(600));
        resetToken.setUsed(false);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("secret-reset-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("secret-reset-token"))
            .thenReturn(Optional.of(resetToken));
        when(passwordEncoder.encode("NewPassword123")).thenReturn("encoded-new-password");
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
            .thenReturn(resetToken);

        userService.resetPassword(request);

        ArgumentCaptor<String> descriptionCaptor = ArgumentCaptor.forClass(String.class);

        verify(auditLogService).logSuccess(
            eq("resetuser"),
            eq("PASSWORD_RESET_SUCCESS"),
            descriptionCaptor.capture()
        );

        String description = descriptionCaptor.getValue();

        assertFalse(description.contains("NewPassword123"));
        assertFalse(description.contains("secret-reset-token"));
        assertFalse(description.contains("encoded-new-password"));
    }

    @Test
    void resetPassword_invalidToken_shouldCreateFailureAuditWithoutTokenValue() {

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("invalid-secret-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("invalid-secret-token"))
            .thenReturn(Optional.empty());

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        ArgumentCaptor<String> descriptionCaptor = ArgumentCaptor.forClass(String.class);

        verify(auditLogService).logFailure(
            isNull(),
            eq("PASSWORD_RESET_INVALID_TOKEN"),
            descriptionCaptor.capture()
        );

        assertFalse(descriptionCaptor.getValue().contains("invalid-secret-token"));
        assertFalse(descriptionCaptor.getValue().contains("NewPassword123"));
    }

    @Test
    void resetPassword_expiredToken_shouldCreateFailureAudit() {

        User user = new User();
        user.setUsername("expireduser");

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken("expired-secret-token");
        resetToken.setUser(user);
        resetToken.setExpiresAt(Instant.now().minusSeconds(60));
        resetToken.setUsed(false);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("expired-secret-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("expired-secret-token"))
            .thenReturn(Optional.of(resetToken));

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        verify(auditLogService).logFailure(
            "expireduser",
            "PASSWORD_RESET_EXPIRED_TOKEN",
            "Password reset failed because the token has expired"
        );

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void resetPassword_reusedToken_shouldCreateFailureAudit() {

        User user = new User();
        user.setUsername("reuseuser");

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken("used-secret-token");
        resetToken.setUser(user);
        resetToken.setExpiresAt(Instant.now().plusSeconds(600));
        resetToken.setUsed(true);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("used-secret-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("used-secret-token"))
            .thenReturn(Optional.of(resetToken));

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        verify(auditLogService).logFailure(
            "reuseuser",
            "PASSWORD_RESET_TOKEN_REUSE",
            "Password reset failed because the token has already been used"
        );

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void createPasswordResetToken_shouldCreateSuccessAudit() {
        User user = new User();
        user.setUsername("requestuser");
        user.setEmail("request@example.com");

        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("request@example.com");

        when(userRepository.findByEmail("request@example.com")).thenReturn(Optional.of(user));
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        String token = userService.createPasswordResetToken(request);

        assertNotNull(token);
        verify(auditLogService).logSuccess(
            "requestuser",
            "PASSWORD_RESET_REQUESTED",
            "Password reset requested"
        );
    }

    @Test
    void enableUser_shouldCreateSuccessAudit() {
        User user = new User();
        user.setId(20L);
        user.setUsername("enableuser");
        user.setEnabled(false);

        when(userRepository.findById(20L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.enableUser(20L);

        assertTrue(user.isEnabled());
        verify(auditLogService).logSuccess(
            "enableuser",
            "USER_ENABLED",
            "User enabled successfully"
        );
    }

    @Test
    void disableUser_shouldCreateSuccessAudit() {
        User user = new User();
        user.setId(21L);
        user.setUsername("disableuser");
        user.setEnabled(true);

        when(userRepository.findById(21L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.disableUser(21L);

        assertFalse(user.isEnabled());
        verify(auditLogService).logSuccess(
            "disableuser",
            "USER_DISABLED",
            "User disabled successfully"
        );
    }

    @Test
    void assignRoleToUser_shouldCreateSuccessAudit() {
        User user = new User();
        user.setId(30L);
        user.setUsername("roleuser");

        Role role = new Role();
        role.setId(2L);
        role.setName("ADMIN");

        when(userRepository.findById(30L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.assignRoleToUser(30L, 2L);

        assertTrue(user.getRoles().contains(role));
        verify(auditLogService).logSuccess(
            "roleuser",
            "ROLE_ASSIGNED",
            "Role 'ADMIN' assigned to user"
        );
    }

    @Test
    void removeRoleFromUser_shouldCreateSuccessAudit() {
        User user = new User();
        user.setId(31L);
        user.setUsername("removeroleuser");

        Role role = new Role();
        role.setId(3L);
        role.setName("ADMIN");
        user.getRoles().add(role);

        when(userRepository.findById(31L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(3L)).thenReturn(Optional.of(role));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.removeRoleFromUser(31L, 3L);

        assertFalse(user.getRoles().contains(role));
        verify(auditLogService).logSuccess(
            "removeroleuser",
            "ROLE_REMOVED",
            "Role 'ADMIN' removed from user"
        );
    }
    @Test
    void assignAuthorityToRole_shouldCreateSuccessAudit() {
        Role role = new Role();
        role.setId(40L);
        role.setName("ADMIN");

        com.zaalima.iam.entity.Authority authority = new com.zaalima.iam.entity.Authority();
        authority.setId(5L);
        authority.setName("USER_READ");

        when(roleRepository.findById(40L)).thenReturn(Optional.of(role));
        when(authorityRepository.findById(5L)).thenReturn(Optional.of(authority));
        when(roleRepository.save(any(Role.class))).thenReturn(role);

        userService.assignAuthorityToRole(40L, 5L);

        assertTrue(role.getAuthorities().contains(authority));
        verify(auditLogService).logSuccess(
            isNull(),
            eq("AUTHORITY_ASSIGNED"),
            eq("Authority 'USER_READ' assigned to role 'ADMIN'")
        );
    }

    @Test
    void removeAuthorityFromRole_shouldCreateSuccessAudit() {
        Role role = new Role();
        role.setId(41L);
        role.setName("ADMIN");

        com.zaalima.iam.entity.Authority authority = new com.zaalima.iam.entity.Authority();
        authority.setId(6L);
        authority.setName("USER_DELETE");
        role.getAuthorities().add(authority);

        when(roleRepository.findById(41L)).thenReturn(Optional.of(role));
        when(authorityRepository.findById(6L)).thenReturn(Optional.of(authority));
        when(roleRepository.save(any(Role.class))).thenReturn(role);

        userService.removeAuthorityFromRole(41L, 6L);

        assertFalse(role.getAuthorities().contains(authority));
        verify(auditLogService).logSuccess(
            isNull(),
            eq("AUTHORITY_REMOVED"),
            eq("Authority 'USER_DELETE' removed from role 'ADMIN'")
        );
    }}
