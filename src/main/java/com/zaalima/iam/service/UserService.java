package com.zaalima.iam.service;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserProfileUpdateRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.entity.Authority;
import com.zaalima.iam.entity.PasswordResetToken;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.InvalidPasswordResetTokenException;
import com.zaalima.iam.exception.UserNotFoundException;
import com.zaalima.iam.repository.AuthorityRepository;
import com.zaalima.iam.repository.PasswordResetTokenRepository;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String DEFAULT_ROLE = "USER";
    private static final Duration PASSWORD_RESET_TOKEN_VALIDITY = Duration.ofMinutes(30);

    private static final String USER_REGISTERED = "USER_REGISTERED";
    private static final String REGISTRATION_FAILED_DUPLICATE_USERNAME = "REGISTRATION_FAILED_DUPLICATE_USERNAME";
    private static final String REGISTRATION_FAILED_DUPLICATE_EMAIL = "REGISTRATION_FAILED_DUPLICATE_EMAIL";
    private static final String USER_PROFILE_UPDATED = "USER_PROFILE_UPDATED";
    private static final String PROFILE_UPDATE_FAILED_DUPLICATE_USERNAME = "PROFILE_UPDATE_FAILED_DUPLICATE_USERNAME";
    private static final String PROFILE_UPDATE_FAILED_DUPLICATE_EMAIL = "PROFILE_UPDATE_FAILED_DUPLICATE_EMAIL";
    private static final String PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED";
    private static final String PASSWORD_RESET_SUCCESS = "PASSWORD_RESET_SUCCESS";
    private static final String PASSWORD_RESET_INVALID_TOKEN = "PASSWORD_RESET_INVALID_TOKEN";
    private static final String PASSWORD_RESET_EXPIRED_TOKEN = "PASSWORD_RESET_EXPIRED_TOKEN";
    private static final String PASSWORD_RESET_TOKEN_REUSE = "PASSWORD_RESET_TOKEN_REUSE";
    private static final String USER_ENABLED = "USER_ENABLED";
    private static final String USER_DISABLED = "USER_DISABLED";
    private static final String ROLE_ASSIGNED = "ROLE_ASSIGNED";
    private static final String ROLE_REMOVED = "ROLE_REMOVED";
    private static final String AUTHORITY_ASSIGNED = "AUTHORITY_ASSIGNED";
    private static final String AUTHORITY_REMOVED = "AUTHORITY_REMOVED";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            auditLogService.logFailure(
                request.getUsername(),
                REGISTRATION_FAILED_DUPLICATE_USERNAME,
                "User registration failed because the username already exists"
            );
            throw new DuplicateUsernameException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            auditLogService.logFailure(
                request.getUsername(),
                REGISTRATION_FAILED_DUPLICATE_EMAIL,
                "User registration failed because the email already exists"
            );
            throw new DuplicateEmailException("Email already exists");
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE)
            .orElseThrow(() -> new IllegalStateException("Default USER role not found"));

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        user.getRoles().add(defaultRole);

        User savedUser = userRepository.save(user);

        auditLogService.logSuccess(
            savedUser.getUsername(),
            USER_REGISTERED,
            "User registration completed successfully"
        );

        return new UserRegistrationResponse(
            savedUser.getId(),
            savedUser.getUsername(),
            savedUser.getEmail(),
            savedUser.isEnabled()
        );
    }

    public UserProfileResponse getUserProfile(Long userId) {

        User user = findUserById(userId);

        return toProfileResponse(user);
    }

    public UserProfileResponse updateUserProfile(
            Long userId,
            UserProfileUpdateRequest request) {

        User user = findUserById(userId);

        if (!user.getUsername().equals(request.getUsername())
                && userRepository.existsByUsername(request.getUsername())) {
            auditLogService.logFailure(
                user.getUsername(),
                PROFILE_UPDATE_FAILED_DUPLICATE_USERNAME,
                "Profile update failed because the username already exists"
            );
            throw new DuplicateUsernameException("Username already exists");
        }

        if (!user.getEmail().equals(request.getEmail())
                && userRepository.existsByEmail(request.getEmail())) {
            auditLogService.logFailure(
                user.getUsername(),
                PROFILE_UPDATE_FAILED_DUPLICATE_EMAIL,
                "Profile update failed because the email already exists"
            );
            throw new DuplicateEmailException("Email already exists");
        }

        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        User updatedUser = userRepository.save(user);

        auditLogService.logSuccess(
            updatedUser.getUsername(),
            USER_PROFILE_UPDATED,
            "User profile updated successfully"
        );

        return toProfileResponse(updatedUser);
    }

    public UserProfileResponse findUserByUsername(String username) {

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        return toProfileResponse(user);
    }

    public UserProfileResponse findUserByEmail(String email) {

        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        return toProfileResponse(user);
    }

    public UserProfileResponse enableUser(Long userId) {

        User user = findUserById(userId);
        user.setEnabled(true);

        User savedUser = userRepository.save(user);

        auditLogService.logSuccess(
            savedUser.getUsername(),
            USER_ENABLED,
            "User enabled successfully"
        );

        return toProfileResponse(savedUser);
    }

    public UserProfileResponse disableUser(Long userId) {

        User user = findUserById(userId);
        user.setEnabled(false);

        User savedUser = userRepository.save(user);

        auditLogService.logSuccess(
            savedUser.getUsername(),
            USER_DISABLED,
            "User disabled successfully"
        );

        return toProfileResponse(savedUser);
    }

    public void assignRoleToUser(Long userId, Long roleId) {

        User user = findUserById(userId);

        Role role = roleRepository.findById(roleId)
            .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        user.getRoles().add(role);
        userRepository.save(user);

        auditLogService.logSuccess(
            user.getUsername(),
            ROLE_ASSIGNED,
            "Role '" + role.getName() + "' assigned to user"
        );
    }

    public void removeRoleFromUser(Long userId, Long roleId) {

        User user = findUserById(userId);

        Role role = roleRepository.findById(roleId)
            .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (!user.getRoles().remove(role)) {
            throw new IllegalArgumentException("Role is not assigned to user");
        }

        userRepository.save(user);

        auditLogService.logSuccess(
            user.getUsername(),
            ROLE_REMOVED,
            "Role '" + role.getName() + "' removed from user"
        );
    }

    public void assignAuthorityToRole(Long roleId, Long authorityId) {

        Role role = roleRepository.findById(roleId)
            .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        Authority authority = authorityRepository.findById(authorityId)
            .orElseThrow(() -> new IllegalArgumentException("Authority not found"));

        role.getAuthorities().add(authority);
        roleRepository.save(role);

        auditLogService.logSuccess(
            null,
            AUTHORITY_ASSIGNED,
            "Authority '" + authority.getName() + "' assigned to role '" + role.getName() + "'"
        );
    }

    public void removeAuthorityFromRole(Long roleId, Long authorityId) {

        Role role = roleRepository.findById(roleId)
            .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        Authority authority = authorityRepository.findById(authorityId)
            .orElseThrow(() -> new IllegalArgumentException("Authority not found"));

        if (!role.getAuthorities().remove(authority)) {
            throw new IllegalArgumentException("Authority is not assigned to role");
        }

        roleRepository.save(role);

        auditLogService.logSuccess(
            null,
            AUTHORITY_REMOVED,
            "Authority '" + authority.getName() + "' removed from role '" + role.getName() + "'"
        );
    }

    public String createPasswordResetToken(ForgotPasswordRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(UUID.randomUUID().toString());
        resetToken.setUser(user);
        resetToken.setExpiresAt(Instant.now().plus(PASSWORD_RESET_TOKEN_VALIDITY));
        resetToken.setUsed(false);

        passwordResetTokenRepository.save(resetToken);

        auditLogService.logSuccess(
            user.getUsername(),
            PASSWORD_RESET_REQUESTED,
            "Password reset requested"
        );

        return resetToken.getToken();
    }

    public void resetPassword(ResetPasswordRequest request) {

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(request.getToken())
            .orElseThrow(() -> {
                auditLogService.logFailure(
                    null,
                    PASSWORD_RESET_INVALID_TOKEN,
                    "Password reset failed because the token is invalid"
                );
                return new InvalidPasswordResetTokenException("Invalid password reset token");
            });

        User user = resetToken.getUser();

        if (resetToken.isUsed()) {
            auditLogService.logFailure(
                user.getUsername(),
                PASSWORD_RESET_TOKEN_REUSE,
                "Password reset failed because the token has already been used"
            );
            throw new InvalidPasswordResetTokenException("Password reset token has already been used");
        }

        if (resetToken.getExpiresAt().isBefore(Instant.now())) {
            auditLogService.logFailure(
                user.getUsername(),
                PASSWORD_RESET_EXPIRED_TOKEN,
                "Password reset failed because the token has expired"
            );
            throw new InvalidPasswordResetTokenException("Password reset token has expired");
        }

        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);

        auditLogService.logSuccess(
            user.getUsername(),
            PASSWORD_RESET_SUCCESS,
            "Password reset completed successfully"
        );
    }

    private User findUserById(Long userId) {

        return userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    private UserProfileResponse toProfileResponse(User user) {

        return new UserProfileResponse(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.isEnabled()
        );
    }
}
