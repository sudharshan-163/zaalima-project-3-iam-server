package com.zaalima.iam.controller;

import com.zaalima.iam.service.AuditLogService;
import com.zaalima.iam.service.MfaChallengeAuthenticationService;
import com.zaalima.iam.service.MfaPendingAuthenticationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaAuthenticationControllerTest {

    @Mock
    private MfaChallengeAuthenticationService mfaChallengeAuthenticationService;

    @Mock
    private MfaPendingAuthenticationService mfaPendingAuthenticationService;

    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private MfaAuthenticationController controller;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void showMfaPage_shouldReturnMfaView() {
        assertEquals("mfa", controller.showMfaPage());
    }

    @Test
    void verifyMfa_shouldRedirectToLoginWhenPendingSessionMissing() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();

        String result = controller.verifyMfa("123456", request, response, redirectAttributes);

        assertEquals("redirect:/login", result);
        assertEquals("MFA session expired. Please login again.", redirectAttributes.getFlashAttributes().get("error"));
        verifyNoInteractions(auditLogService);
    }

    @Test
    void verifyMfa_shouldAuditFailureWhenCodeIsInvalid() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();
        request.getSession().setAttribute("MFA_USERNAME", "testuser");

        Authentication authentication =
                new UsernamePasswordAuthenticationToken("testuser", null);
        when(mfaPendingAuthenticationService.get("testuser")).thenReturn(authentication);
        when(mfaChallengeAuthenticationService.verifyChallenge("testuser", "123456")).thenReturn(false);

        String result = controller.verifyMfa("123456", request, response, redirectAttributes);

        assertEquals("redirect:/mfa", result);
        verify(auditLogService).logFailure(
                "testuser",
                "LOGIN_FAILED_MFA",
                "User authentication failed because MFA verification was invalid or expired"
        );
        assertEquals("Invalid or expired MFA code.", redirectAttributes.getFlashAttributes().get("error"));
        verify(auditLogService, never()).logSuccess(anyString(), anyString(), anyString());
    }

    @Test
    void verifyMfa_shouldRedirectToDefaultProfileWhenNoSavedRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();
        request.getSession().setAttribute("MFA_USERNAME", "testuser");

        Authentication authentication =
                new UsernamePasswordAuthenticationToken("testuser", null);
        when(mfaPendingAuthenticationService.get("testuser")).thenReturn(authentication);
        when(mfaChallengeAuthenticationService.verifyChallenge("testuser", "123456")).thenReturn(true);

        String result = controller.verifyMfa("123456", request, response, redirectAttributes);

        assertEquals("redirect:/api/users/me", result);
        verify(mfaPendingAuthenticationService).remove("testuser");
        verify(auditLogService).logSuccess(
                "testuser",
                "LOGIN_SUCCESS",
                "User authentication completed successfully after MFA verification"
        );
    }

    @Test
    void verifyMfa_shouldResumeSavedOAuth2RequestWhenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();
        request.getSession().setAttribute("MFA_USERNAME", "testuser");

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        String oauth2AuthorizeUrl = "http://localhost:8085/oauth2/authorize?client_id=iam-client&response_type=code&scope=openid&code_challenge=xyz&code_challenge_method=S256";
        when(savedRequest.getRedirectUrl()).thenReturn(oauth2AuthorizeUrl);
        request.getSession().setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);

        Authentication authentication =
                new UsernamePasswordAuthenticationToken("testuser", null);
        when(mfaPendingAuthenticationService.get("testuser")).thenReturn(authentication);
        when(mfaChallengeAuthenticationService.verifyChallenge("testuser", "123456")).thenReturn(true);

        String result = controller.verifyMfa("123456", request, response, redirectAttributes);

        assertEquals("redirect:" + oauth2AuthorizeUrl, result);
        verify(mfaPendingAuthenticationService).remove("testuser");
    }
}