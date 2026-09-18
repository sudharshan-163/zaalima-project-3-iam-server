package com.zaalima.iam.service;

import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    @Test
    void shouldLoadUserByUsername() {
        User user = new User();
        user.setId(1L);
        user.setUsername("sudharshan");
        user.setPassword("$2a$10$hashedPassword");
        user.setEnabled(true);

        Role role = new Role();
        role.setName("USER");

        user.getRoles().add(role);

        when(userRepository.findByUsername("sudharshan"))
                .thenReturn(Optional.of(user));

        UserDetails userDetails =
                customUserDetailsService.loadUserByUsername("sudharshan");

        assertEquals("sudharshan", userDetails.getUsername());
        assertEquals("$2a$10$hashedPassword", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
        assertTrue(
                userDetails.getAuthorities()
                        .stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_USER"))
        );

        verify(userRepository).findByUsername("sudharshan");
    }

    @Test
    void shouldThrowExceptionWhenUserDoesNotExist() {
        when(userRepository.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(
                UsernameNotFoundException.class,
                () -> customUserDetailsService.loadUserByUsername("unknown")
        );

        verify(userRepository).findByUsername("unknown");
    }

    @Test
    void shouldDisableUserWhenEnabledIsFalse() {
        User user = new User();
        user.setUsername("disabledUser");
        user.setPassword("encodedPassword");
        user.setEnabled(false);

        when(userRepository.findByUsername("disabledUser"))
                .thenReturn(Optional.of(user));

        UserDetails userDetails =
                customUserDetailsService.loadUserByUsername("disabledUser");

        assertFalse(userDetails.isEnabled());
    }
}
