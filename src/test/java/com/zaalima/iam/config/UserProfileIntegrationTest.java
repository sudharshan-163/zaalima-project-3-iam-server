package com.zaalima.iam.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaalima.iam.dto.UserProfileUpdateRequest;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserProfileIntegrationTest {

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
    void setUp() {
        Role defaultRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName("USER");
                    return roleRepository.save(role);
                });

        if (userRepository.findByUsername("profile_user").isEmpty()) {
            User existingUser = new User();
            existingUser.setUsername("profile_user");
            existingUser.setEmail("profile_user@example.com");
            existingUser.setPassword(passwordEncoder.encode("Password123!"));
            existingUser.setEnabled(true);
            existingUser.getRoles().add(defaultRole);
            userRepository.save(existingUser);
        }
    }

    @Test
    void getCurrentUserProfile_unauthenticated_shouldRedirectToLogin() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "profile_user")
    void getCurrentUserProfile_authenticated_shouldReturnProfile() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("profile_user"))
                .andExpect(jsonPath("$.email").value("profile_user@example.com"))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    @WithMockUser(username = "profile_user")
    void updateCurrentUserProfile_validRequest_shouldUpdateAndReturnProfile() throws Exception {
        UserProfileUpdateRequest request = new UserProfileUpdateRequest();
        request.setUsername("updated_username");
        request.setEmail("updated_email@example.com");

        mockMvc.perform(put("/api/users/me")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("updated_username"))
                .andExpect(jsonPath("$.email").value("updated_email@example.com"));

        User refreshed = userRepository.findByUsername("updated_username").orElseThrow();
        assertEquals("updated_email@example.com", refreshed.getEmail());
    }

    @Test
    @WithMockUser(username = "profile_user")
    void updateCurrentUserProfile_duplicateEmail_shouldReturnConflict() throws Exception {
        Role defaultRole = roleRepository.findByName("USER").orElseThrow();
        User otherUser = new User();
        otherUser.setUsername("other_user");
        otherUser.setEmail("other_user@example.com");
        otherUser.setPassword(passwordEncoder.encode("Password123!"));
        otherUser.setEnabled(true);
        otherUser.getRoles().add(defaultRole);
        userRepository.save(otherUser);

        UserProfileUpdateRequest request = new UserProfileUpdateRequest();
        request.setUsername("profile_user");
        request.setEmail("other_user@example.com");

        mockMvc.perform(put("/api/users/me")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }
}
