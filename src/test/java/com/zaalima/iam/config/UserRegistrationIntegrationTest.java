package com.zaalima.iam.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserRegistrationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void ensureDefaultRoleExists() {
        if (roleRepository.findByName("USER").isEmpty()) {
            Role role = new Role();
            role.setName("USER");
            roleRepository.save(role);
        }
    }

    @Test
    void registerUser_shouldPersistUserWithBCryptHashedPasswordAndDefaultRole() throws Exception {
        String rawPassword = "StrongPassword123!";
        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("reg_test_user");
        request.setEmail("reg_test@example.com");
        request.setPassword(rawPassword);

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.username").value("reg_test_user"))
                .andExpect(jsonPath("$.email").value("reg_test@example.com"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(content().string(not(containsString(rawPassword))));

        User persistedUser = userRepository.findByUsername("reg_test_user")
                .orElseThrow(() -> new AssertionError("User was not persisted to the database"));

        assertNotNull(persistedUser.getId());
        assertEquals("reg_test_user", persistedUser.getUsername());
        assertEquals("reg_test@example.com", persistedUser.getEmail());
        assertTrue(persistedUser.isEnabled());

        // Verify password is BCrypt hashed and never stored as raw plain-text
        assertNotEquals(rawPassword, persistedUser.getPassword());
        assertTrue(persistedUser.getPassword().startsWith("$2a$") || persistedUser.getPassword().startsWith("$2b$"),
                "Password hash should follow standard BCrypt prefix ($2a$ or $2b$)");
        assertTrue(passwordEncoder.matches(rawPassword, persistedUser.getPassword()),
                "BCrypt password encoder must match the raw password against the database hash");

        // Verify default role assignment
        boolean hasDefaultRole = persistedUser.getRoles().stream()
                .anyMatch(r -> "USER".equals(r.getName()));
        assertTrue(hasDefaultRole, "Registered user must have the default 'USER' role assigned");
    }

    @Test
    void registerUser_shouldRejectDuplicateUsernameWithConflict() throws Exception {
        UserRegistrationRequest firstRequest = new UserRegistrationRequest();
        firstRequest.setUsername("dup_user");
        firstRequest.setEmail("dup1@example.com");
        firstRequest.setPassword("Password123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstRequest)))
                .andExpect(status().isCreated());

        UserRegistrationRequest duplicateRequest = new UserRegistrationRequest();
        duplicateRequest.setUsername("dup_user");
        duplicateRequest.setEmail("different@example.com");
        duplicateRequest.setPassword("Password123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Username already exists"));
    }

    @Test
    void registerUser_shouldRejectDuplicateEmailWithConflict() throws Exception {
        UserRegistrationRequest firstRequest = new UserRegistrationRequest();
        firstRequest.setUsername("email_user_1");
        firstRequest.setEmail("shared@example.com");
        firstRequest.setPassword("Password123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstRequest)))
                .andExpect(status().isCreated());

        UserRegistrationRequest duplicateRequest = new UserRegistrationRequest();
        duplicateRequest.setUsername("email_user_2");
        duplicateRequest.setEmail("shared@example.com");
        duplicateRequest.setPassword("Password123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Email already exists"));
    }

    @Test
    void registerUser_shouldRejectInvalidInputsWithBadRequest() throws Exception {
        UserRegistrationRequest invalidRequest = new UserRegistrationRequest();
        invalidRequest.setUsername("");
        invalidRequest.setEmail("invalid-email-address");
        invalidRequest.setPassword("short");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }
}
