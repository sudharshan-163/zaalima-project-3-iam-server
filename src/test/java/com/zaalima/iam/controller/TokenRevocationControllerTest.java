package com.zaalima.iam.controller;

import com.zaalima.iam.service.TokenRevocationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TokenRevocationController.class)
@Import(com.zaalima.iam.exception.GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class TokenRevocationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TokenRevocationService tokenRevocationService;

    @Test
    void revokeToken_shouldReturnNoContent() throws Exception {

        String requestBody = """
                {
                    "jti": "test-jti",
                    "expiresAt": 4102444800
                }
                """;

        mockMvc.perform(post("/api/tokens/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isNoContent());

        verify(tokenRevocationService).revokeUntil(
                "test-jti",
                4102444800L
        );
    }

    @Test
    void revokeToken_shouldRejectBlankJti() throws Exception {

        String requestBody = """
                {
                    "jti": "",
                    "expiresAt": 4102444800
                }
                """;

        mockMvc.perform(post("/api/tokens/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void revokeToken_shouldReturnBadRequestWhenTokenAlreadyExpired()
            throws Exception {

        doThrow(new IllegalArgumentException("Token has already expired"))
                .when(tokenRevocationService)
                .revokeUntil(anyString(), anyLong());

        String requestBody = """
                {
                    "jti": "expired-jti",
                    "expiresAt": 1
                }
                """;

        mockMvc.perform(post("/api/tokens/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }
}