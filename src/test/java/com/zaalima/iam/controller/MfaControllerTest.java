package com.zaalima.iam.controller;

import com.zaalima.iam.dto.MfaCodeRequest;
import com.zaalima.iam.service.MfaService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class MfaControllerTest {

    @Test
    void enableShouldRejectInvalidCode() {
        MfaService mfaService = mock(MfaService.class);
        Authentication authentication = mock(Authentication.class);
        MfaController controller = new MfaController(mfaService);

        when(authentication.getName()).thenReturn("testuser");
        when(mfaService.verifySetupCode("testuser", "123456"))
                .thenReturn(false);

        MfaCodeRequest request = new MfaCodeRequest();
        request.setCode("123456");

        ResponseEntity<String> response =
                controller.enable(request, authentication);

        assertEquals(400, response.getStatusCode().value());
        assertEquals("Invalid MFA code", response.getBody());
        verify(mfaService, never()).enableMfa("testuser");
    }

    @Test
    void enableShouldEnableMfaWhenCodeIsValid() {
        MfaService mfaService = mock(MfaService.class);
        Authentication authentication = mock(Authentication.class);
        MfaController controller = new MfaController(mfaService);

        when(authentication.getName()).thenReturn("testuser");
        when(mfaService.verifySetupCode("testuser", "123456"))
                .thenReturn(true);

        MfaCodeRequest request = new MfaCodeRequest();
        request.setCode("123456");

        ResponseEntity<String> response =
                controller.enable(request, authentication);

        assertEquals(200, response.getStatusCode().value());
        assertEquals("MFA enabled", response.getBody());
        verify(mfaService).enableMfa("testuser");
    }
}