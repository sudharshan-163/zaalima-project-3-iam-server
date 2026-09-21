package com.zaalima.iam.service;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.entity.Authority;
import com.zaalima.iam.entity.PasswordResetToken;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.InvalidPasswordResetTokenException;
import com.zaalima.iam.exception.UserNotFoundException;
import com.zaalima.iam.repository.AuthorityRepository;
import com.zaalima.iam.repository.PasswordResetTokenRepository;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AuthorityRepository authorityRepository;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void assignRoleToUser_shouldAssignRoleWithoutDuplicate() {
        User user = new User();
        Role role = new Role();
        role.setId(2L);
        role.setName("ADMIN");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));

        userService.assignRoleToUser(1L, 2L);
        userService.assignRoleToUser(1L, 2L);

        assertEquals(1, user.getRoles().size());
        assertTrue(user.getRoles().contains(role));
        verify(userRepository, times(2)).save(user);
    }

    @Test
    void removeRoleFromUser_shouldRemoveAssignedRole() {
        User user = new User();
        Role role = new Role();
        role.setId(2L);
        role.setName("ADMIN");
        user.getRoles().add(role);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));

        userService.removeRoleFromUser(1L, 2L);

        assertTrue(user.getRoles().isEmpty());
        verify(userRepository).save(user);
    }

    @Test
    void assignAuthorityToRole_shouldAssignAuthorityWithoutDuplicate() {
        Role role = new Role();
        Authority authority = new Authority();
        authority.setId(3L);
        authority.setName("USER_READ");

        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));
        when(authorityRepository.findById(3L)).thenReturn(Optional.of(authority));

        userService.assignAuthorityToRole(2L, 3L);
        userService.assignAuthorityToRole(2L, 3L);

        assertEquals(1, role.getAuthorities().size());
        assertTrue(role.getAuthorities().contains(authority));
        verify(roleRepository, times(2)).save(role);
    }

    @Test
    void removeAuthorityFromRole_shouldRemoveAssignedAuthority() {
        Role role = new Role();
        Authority authority = new Authority();
        authority.setId(3L);
        authority.setName("USER_READ");
        role.getAuthorities().add(authority);

        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));
        when(authorityRepository.findById(3L)).thenReturn(Optional.of(authority));

        userService.removeAuthorityFromRole(2L, 3L);

        assertTrue(role.getAuthorities().isEmpty());
        verify(roleRepository).save(role);
    }

    @Test
    void enableUser_shouldEnableDisabledUser() {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setEnabled(false);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        UserProfileResponse response = userService.enableUser(1L);

        assertTrue(user.isEnabled());
        assertTrue(response.isEnabled());
        verify(userRepository).save(user);
    }

    @Test
    void disableUser_shouldDisableEnabledUser() {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setEnabled(true);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        UserProfileResponse response = userService.disableUser(1L);

        assertFalse(user.isEnabled());
        assertFalse(response.isEnabled());
        verify(userRepository).save(user);
    }

    @Test
    void assignRoleToUser_shouldRejectInvalidUser() {
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(
            UserNotFoundException.class,
            () -> userService.assignRoleToUser(999L, 2L)
        );

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void resetPassword_shouldEncodeNewPasswordAndMarkTokenUsed() {
        User user = new User();
        user.setId(1L);
        user.setUsername("resetuser");
        user.setEmail("reset@example.com");

        PasswordResetToken token = new PasswordResetToken();
        token.setToken("valid-token");
        token.setUser(user);
        token.setExpiresAt(Instant.now().plusSeconds(600));
        token.setUsed(false);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("valid-token");
        request.setPassword("NewPassword123");

        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        String encodedPassword = bcrypt.encode("NewPassword123");

        when(passwordResetTokenRepository.findByToken("valid-token"))
            .thenReturn(Optional.of(token));
        when(passwordEncoder.encode("NewPassword123"))
            .thenReturn(encodedPassword);
        when(userRepository.save(user)).thenReturn(user);
        when(passwordResetTokenRepository.save(token)).thenReturn(token);

        userService.resetPassword(request);

        assertNotEquals("NewPassword123", user.getPassword());
        assertTrue(bcrypt.matches("NewPassword123", user.getPassword()));
        assertTrue(token.isUsed());

        verify(userRepository).save(user);
        verify(passwordResetTokenRepository).save(token);
    }

    @Test
    void resetPassword_shouldRejectExpiredToken() {
        User user = new User();
        PasswordResetToken token = new PasswordResetToken();
        token.setToken("expired-token");
        token.setUser(user);
        token.setExpiresAt(Instant.now().minusSeconds(60));
        token.setUsed(false);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("expired-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("expired-token"))
            .thenReturn(Optional.of(token));

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        verify(userRepository, never()).save(any(User.class));
        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    void resetPassword_shouldRejectUsedToken() {
        User user = new User();
        PasswordResetToken token = new PasswordResetToken();
        token.setToken("used-token");
        token.setUser(user);
        token.setExpiresAt(Instant.now().plusSeconds(600));
        token.setUsed(true);

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("used-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("used-token"))
            .thenReturn(Optional.of(token));

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        verify(userRepository, never()).save(any(User.class));
        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    void resetPassword_shouldRejectInvalidToken() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("invalid-token");
        request.setPassword("NewPassword123");

        when(passwordResetTokenRepository.findByToken("invalid-token"))
            .thenReturn(Optional.empty());

        assertThrows(
            InvalidPasswordResetTokenException.class,
            () -> userService.resetPassword(request)
        );

        verify(userRepository, never()).save(any(User.class));
    }
}
