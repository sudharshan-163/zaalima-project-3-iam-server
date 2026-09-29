package com.zaalima.iam.controller;

import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.GlobalExceptionHandler;
import com.zaalima.iam.exception.UserNotFoundException;
import com.zaalima.iam.service.TokenRevocationService;
import com.zaalima.iam.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private TokenRevocationService tokenRevocationService;

    @Test
    void register_shouldReturnCreated() throws Exception {
        UserRegistrationResponse response =
                new UserRegistrationResponse(
                        1L,
                        "testuser",
                        "test@example.com",
                        true
                );

        when(userService.registerUser(any())).thenReturn(response);

        String requestBody = """
                {
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "Password123!"
                }
                """;

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void getCurrentUserProfile_shouldReturnProfileFromSecurityContext() throws Exception {
        UserProfileResponse response = new UserProfileResponse(10L, "current_user", "current@example.com", true);

        when(userService.getCurrentUserProfile("current_user")).thenReturn(response);

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("current_user", null, Collections.emptyList());

        mockMvc.perform(get("/api/users/me")
                        .principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(10L))
                .andExpect(jsonPath("$.username").value("current_user"))
                .andExpect(jsonPath("$.email").value("current@example.com"));
    }

    @Test
    void updateCurrentUserProfile_shouldUpdateProfileFromSecurityContext() throws Exception {
        UserProfileResponse response = new UserProfileResponse(10L, "new_username", "new_email@example.com", true);

        when(userService.updateCurrentUserProfile(eq("current_user"), any())).thenReturn(response);

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("current_user", null, Collections.emptyList());

        String updateBody = """
                {
                    "username": "new_username",
                    "email": "new_email@example.com"
                }
                """;

        mockMvc.perform(put("/api/users/me")
                        .principal(auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("new_username"))
                .andExpect(jsonPath("$.email").value("new_email@example.com"));
    }

    @Test
    void getProfile_shouldReturnProfile() throws Exception {
        UserProfileResponse response = new UserProfileResponse(1L, "testuser", "test@example.com", true);

        when(userService.getUserProfile(1L)).thenReturn(response);

        mockMvc.perform(get("/api/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void getProfile_shouldReturnNotFound_whenUserDoesNotExist() throws Exception {
        when(userService.getUserProfile(999L)).thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(get("/api/users/999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void updateProfile_shouldReturnConflict_whenUsernameTaken() throws Exception {
        when(userService.updateUserProfile(eq(1L), any()))
                .thenThrow(new DuplicateUsernameException("Username already exists"));

        String requestBody = """
                {
                    "username": "existinguser",
                    "email": "test@example.com"
                }
                """;

        mockMvc.perform(put("/api/users/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict());
    }

    @Test
    void updateProfile_shouldReturnConflict_whenEmailTaken() throws Exception {
        when(userService.updateUserProfile(eq(1L), any()))
                .thenThrow(new DuplicateEmailException("Email already exists"));

        String requestBody = """
                {
                    "username": "testuser",
                    "email": "existing@example.com"
                }
                """;

        mockMvc.perform(put("/api/users/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict());
    }
}
