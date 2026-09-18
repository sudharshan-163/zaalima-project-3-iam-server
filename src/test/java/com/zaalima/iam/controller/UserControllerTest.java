package com.zaalima.iam.controller;

import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.GlobalExceptionHandler;
import com.zaalima.iam.exception.UserNotFoundException;
import com.zaalima.iam.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
                    "password": "Password123"
                }
                """;

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("password")
                )));
    }

    @Test
    void register_shouldRejectInvalidRequest() throws Exception {

        String requestBody = """
                {
                    "username": "",
                    "email": "invalid-email",
                    "password": "short"
                }
                """;

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_shouldReturnConflictForDuplicateUsername() throws Exception {

        when(userService.registerUser(any()))
                .thenThrow(new DuplicateUsernameException("Username already exists"));

        String requestBody = """
                {
                    "username": "existinguser",
                    "email": "new@example.com",
                    "password": "Password123"
                }
                """;

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Username already exists"));
    }

    @Test
    void register_shouldReturnConflictForDuplicateEmail() throws Exception {

        when(userService.registerUser(any()))
                .thenThrow(new DuplicateEmailException("Email already exists"));

        String requestBody = """
                {
                    "username": "newuser",
                    "email": "existing@example.com",
                    "password": "Password123"
                }
                """;

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Email already exists"));
    }

    @Test
    void getProfile_shouldReturnUserProfile() throws Exception {

        UserProfileResponse response =
                new UserProfileResponse(
                        1L,
                        "profileuser",
                        "profile@example.com",
                        true
                );

        when(userService.getUserProfile(1L)).thenReturn(response);

        mockMvc.perform(get("/api/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.username").value("profileuser"))
                .andExpect(jsonPath("$.email").value("profile@example.com"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("password")
                )));
    }

    @Test
    void getProfile_shouldReturnNotFound() throws Exception {

        when(userService.getUserProfile(999L))
                .thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(get("/api/users/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    void updateProfile_shouldReturnUpdatedProfile() throws Exception {

        UserProfileResponse response =
                new UserProfileResponse(
                        1L,
                        "updateduser",
                        "updated@example.com",
                        true
                );

        when(userService.updateUserProfile(
                org.mockito.ArgumentMatchers.eq(1L),
                any()
        )).thenReturn(response);

        String requestBody = """
                {
                    "username": "updateduser",
                    "email": "updated@example.com"
                }
                """;

        mockMvc.perform(put("/api/users/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.username").value("updateduser"))
                .andExpect(jsonPath("$.email").value("updated@example.com"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("password")
                )));
    }

    @Test
    void updateProfile_shouldRejectInvalidRequest() throws Exception {

        String requestBody = """
                {
                    "username": "",
                    "email": "invalid-email"
                }
                """;

        mockMvc.perform(put("/api/users/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }
}
