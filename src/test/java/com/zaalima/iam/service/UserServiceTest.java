package com.zaalima.iam.service;

import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserProfileUpdateRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.UserNotFoundException;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

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
    void registerUser_shouldCreateUserWithDefaultRole() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("testuser")).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("Password123")).thenReturn("encoded-password");

        User savedUser = new User();
        savedUser.setId(1L);
        savedUser.setUsername("testuser");
        savedUser.setEmail("test@example.com");
        savedUser.setPassword("encoded-password");
        savedUser.setEnabled(true);
        savedUser.getRoles().add(userRole);

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        UserRegistrationResponse response = userService.registerUser(request);

        assertNotNull(response);
        assertEquals(1L, response.getId());
        assertEquals("testuser", response.getUsername());
        assertEquals("test@example.com", response.getEmail());
        assertTrue(response.isEnabled());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User capturedUser = userCaptor.getValue();

        assertEquals("testuser", capturedUser.getUsername());
        assertEquals("test@example.com", capturedUser.getEmail());
        assertEquals("encoded-password", capturedUser.getPassword());
        assertTrue(capturedUser.isEnabled());
        assertTrue(capturedUser.getRoles().contains(userRole));

        verify(passwordEncoder).encode("Password123");
    }

    @Test
    void registerUser_shouldHashPasswordUsingPasswordEncoder() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("hashuser");
        request.setEmail("hash@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("hashuser")).thenReturn(false);
        when(userRepository.existsByEmail("hash@example.com")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("Password123")).thenReturn("bcrypt-hash");

        User savedUser = new User();
        savedUser.setId(2L);
        savedUser.setUsername("hashuser");
        savedUser.setEmail("hash@example.com");
        savedUser.setPassword("bcrypt-hash");
        savedUser.setEnabled(true);
        savedUser.getRoles().add(userRole);

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        userService.registerUser(request);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        assertEquals("bcrypt-hash", userCaptor.getValue().getPassword());
        assertNotEquals("Password123", userCaptor.getValue().getPassword());
    }

    @Test
    void registerUser_shouldRejectDuplicateUsername() {

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("existinguser");
        request.setEmail("new@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        assertThrows(
            DuplicateUsernameException.class,
            () -> userService.registerUser(request)
        );

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void registerUser_shouldRejectDuplicateEmail() {

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

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void bcryptPasswordEncoder_shouldMatchOriginalPassword() {

        PasswordEncoder bcrypt = new BCryptPasswordEncoder();

        String rawPassword = "Password123";
        String encodedPassword = bcrypt.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(bcrypt.matches(rawPassword, encodedPassword));
        assertFalse(bcrypt.matches("WrongPassword", encodedPassword));
    }

    @Test
    void getUserProfile_shouldReturnUserProfile() {

        User user = new User();
        user.setId(1L);
        user.setUsername("profileuser");
        user.setEmail("profile@example.com");
        user.setEnabled(true);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        UserProfileResponse response = userService.getUserProfile(1L);

        assertNotNull(response);
        assertEquals(1L, response.getId());
        assertEquals("profileuser", response.getUsername());
        assertEquals("profile@example.com", response.getEmail());
        assertTrue(response.isEnabled());
    }

    @Test
    void getUserProfile_shouldReturnDisabledUserProfile() {

        User user = new User();
        user.setId(2L);
        user.setUsername("disableduser");
        user.setEmail("disabled@example.com");
        user.setEnabled(false);

        when(userRepository.findById(2L)).thenReturn(Optional.of(user));

        UserProfileResponse response = userService.getUserProfile(2L);

        assertNotNull(response);
        assertEquals(2L, response.getId());
        assertEquals("disableduser", response.getUsername());
        assertEquals("disabled@example.com", response.getEmail());
        assertFalse(response.isEnabled());
    }
    @Test
    void getUserProfile_shouldThrowExceptionWhenUserNotFound() {

        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(
            UserNotFoundException.class,
            () -> userService.getUserProfile(999L)
        );
    }

    @Test
    void updateUserProfile_shouldUpdateUsernameAndEmail() {

        User user = new User();
        user.setId(1L);
        user.setUsername("olduser");
        user.setEmail("old@example.com");
        user.setEnabled(true);

        UserProfileUpdateRequest request = new UserProfileUpdateRequest();
        request.setUsername("newuser");
        request.setEmail("new@example.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(user);

        UserProfileResponse response = userService.updateUserProfile(1L, request);

        assertNotNull(response);
        assertEquals("newuser", response.getUsername());
        assertEquals("new@example.com", response.getEmail());

        assertEquals("newuser", user.getUsername());
        assertEquals("new@example.com", user.getEmail());

        verify(userRepository).save(user);
    }

    @Test
    void updateUserProfile_shouldRejectDuplicateUsername() {

        User user = new User();
        user.setId(1L);
        user.setUsername("olduser");
        user.setEmail("old@example.com");

        UserProfileUpdateRequest request = new UserProfileUpdateRequest();
        request.setUsername("existinguser");
        request.setEmail("old@example.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        assertThrows(
            DuplicateUsernameException.class,
            () -> userService.updateUserProfile(1L, request)
        );

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void updateUserProfile_shouldRejectDuplicateEmail() {

        User user = new User();
        user.setId(1L);
        user.setUsername("olduser");
        user.setEmail("old@example.com");

        UserProfileUpdateRequest request = new UserProfileUpdateRequest();
        request.setUsername("olduser");
        request.setEmail("existing@example.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        assertThrows(
            DuplicateEmailException.class,
            () -> userService.updateUserProfile(1L, request)
        );

        verify(userRepository, never()).save(any(User.class));
    }
}

