package com.zaalima.iam.config;

import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import com.zaalima.iam.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AuthenticationIntegrationTest {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void cleanUsers() {
        userRepository.deleteAll();
    }

    @Test
    void shouldAuthenticateUserWithCorrectPassword() {
        User user = new User();
        user.setUsername("auth_test_user");
        user.setEmail("auth_test@example.com");
        user.setPassword(passwordEncoder.encode("Test@123"));
        user.setEnabled(true);

        userRepository.save(user);

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                "auth_test_user",
                                "Test@123"
                        )
                );

        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
        assertEquals("auth_test_user", authentication.getName());
    }

    @Test
    void shouldRejectUserWithWrongPassword() {
        User user = new User();
        user.setUsername("wrong_password_user");
        user.setEmail("wrong_password@example.com");
        user.setPassword(passwordEncoder.encode("Correct@123"));
        user.setEnabled(true);

        userRepository.save(user);

        assertThrows(
                BadCredentialsException.class,
                () -> authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                "wrong_password_user",
                                "Wrong@123"
                        )
                )
        );
    }

    @Test
    void shouldRejectDisabledUser() {
        User user = new User();
        user.setUsername("disabled_auth_user");
        user.setEmail("disabled_auth@example.com");
        user.setPassword(passwordEncoder.encode("Test@123"));
        user.setEnabled(false);

        userRepository.save(user);

        assertThrows(
                DisabledException.class,
                () -> authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                "disabled_auth_user",
                                "Test@123"
                        )
                )
        );
    }

    @Test
    @Transactional
    void registeredUserShouldHaveDefaultRoleAndAuthenticateWithEncodedPassword() {
        String rawPassword = "Register@123";

        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("registered_auth_user");
        request.setEmail("registered_auth@example.com");
        request.setPassword(rawPassword);

        UserRegistrationResponse response =
                userService.registerUser(request);

        assertNotNull(response);
        assertEquals("registered_auth_user", response.getUsername());
        assertEquals("registered_auth@example.com", response.getEmail());
        assertTrue(response.isEnabled());

        User savedUser =
                userRepository.findByUsername("registered_auth_user")
                        .orElseThrow();

        assertNotEquals(rawPassword, savedUser.getPassword());

        assertTrue(
                passwordEncoder.matches(
                        rawPassword,
                        savedUser.getPassword()
                )
        );

        assertTrue(
                savedUser.getRoles().stream()
                        .anyMatch(role -> role.getName().equals("USER"))
        );

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                "registered_auth_user",
                                rawPassword
                        )
                );

        assertTrue(authentication.isAuthenticated());
        assertEquals("registered_auth_user", authentication.getName());

        assertTrue(
                authentication.getAuthorities().stream()
                        .anyMatch(authority ->
                                authority.getAuthority().equals("ROLE_USER"))
        );

        assertFalse(
                authentication.getAuthorities().stream()
                        .anyMatch(authority ->
                                authority.getAuthority().equals(rawPassword))
        );
    }
}

