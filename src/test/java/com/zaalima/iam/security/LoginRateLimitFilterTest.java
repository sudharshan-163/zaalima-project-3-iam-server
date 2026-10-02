package com.zaalima.iam.security;

import com.zaalima.iam.service.LoginRateLimitService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginRateLimitFilterTest {

    @Mock
    private LoginRateLimitService loginRateLimitService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private LoginRateLimitFilter loginRateLimitFilter;

    @Nested
    @DisplayName("Login Request Rate Limiting")
    class LoginRequestTests {

        @Test
        @DisplayName("Should allow POST /login when rate limit service returns true")
        void shouldAllowLoginWhenRateLimitAllowsRequest() throws Exception {
            when(loginRateLimitService.isAllowed("127.0.0.1", "test_user")).thenReturn(true);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
            request.setRemoteAddr("127.0.0.1");
            request.addParameter("username", "test_user");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verify(loginRateLimitService).isAllowed("127.0.0.1", "test_user");
            verify(filterChain).doFilter(request, response);
            assertEquals(200, response.getStatus());
        }

        @Test
        @DisplayName("Should return 429 Too Many Requests when rate limit service returns false")
        void shouldReturn429WhenRateLimitExceeded() throws Exception {
            when(loginRateLimitService.isAllowed("127.0.0.1", "test_user")).thenReturn(false);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
            request.setRemoteAddr("127.0.0.1");
            request.addParameter("username", "test_user");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verify(loginRateLimitService).isAllowed("127.0.0.1", "test_user");
            verifyNoInteractions(filterChain);

            assertEquals(429, response.getStatus());
            assertEquals("application/json", response.getContentType());
            assertEquals(
                    "{\"error\":\"too_many_requests\",\"message\":\"Too many login attempts. Please try again later.\"}",
                    response.getContentAsString()
            );
        }

        @Test
        @DisplayName("Should pass null username to service when parameter is omitted without throwing exception")
        void shouldHandleMissingUsernameParameter() throws Exception {
            when(loginRateLimitService.isAllowed("127.0.0.1", null)).thenReturn(true);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
            request.setRemoteAddr("127.0.0.1");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verify(loginRateLimitService).isAllowed("127.0.0.1", null);
            verify(filterChain).doFilter(request, response);
            assertEquals(200, response.getStatus());
        }
    }

    @Nested
    @DisplayName("Bypass Non-Target Requests")
    class BypassFilterTests {

        @Test
        @DisplayName("Should not rate limit GET /login")
        void shouldNotRateLimitGetLoginPage() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
            request.setRemoteAddr("127.0.0.1");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verifyNoInteractions(loginRateLimitService);
            verify(filterChain).doFilter(request, response);
        }

        @ParameterizedTest
        @ValueSource(strings = {"PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"})
        @DisplayName("Should not rate limit non-POST methods to /login")
        void shouldNotRateLimitNonPostMethodsToLogin(String httpMethod) throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest(httpMethod, "/login");
            request.setRemoteAddr("127.0.0.1");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verifyNoInteractions(loginRateLimitService);
            verify(filterChain).doFilter(request, response);
        }

        @ParameterizedTest
        @ValueSource(strings = {"/register", "/oauth2/token", "/oauth2/authorize", "/api/users", "/login/status", "/error"})
        @DisplayName("Should not rate limit requests to non-login endpoints")
        void shouldNotRateLimitOtherEndpoints(String endpointUri) throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", endpointUri);
            request.setRemoteAddr("127.0.0.1");
            request.addParameter("username", "test_user");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verifyNoInteractions(loginRateLimitService);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    @DisplayName("Client IP Resolution")
    class ClientIpResolutionTests {

        @Test
        @DisplayName("Should extract first client IP from multi-hop X-Forwarded-For header")
        void shouldExtractFirstClientIpFromMultiHopForwardedFor() throws Exception {
            when(loginRateLimitService.isAllowed("203.0.113.195", "test_user")).thenReturn(true);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
            request.setRemoteAddr("10.0.0.1");
            request.addHeader("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178");
            request.addParameter("username", "test_user");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verify(loginRateLimitService).isAllowed("203.0.113.195", "test_user");
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Should fallback to RemoteAddr when X-Forwarded-For is blank or whitespace")
        void shouldFallbackToRemoteAddrWhenForwardedForIsBlank() throws Exception {
            when(loginRateLimitService.isAllowed("192.168.1.50", "test_user")).thenReturn(true);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
            request.setRemoteAddr("192.168.1.50");
            request.addHeader("X-Forwarded-For", "   ");
            request.addParameter("username", "test_user");

            MockHttpServletResponse response = new MockHttpServletResponse();

            loginRateLimitFilter.doFilter(request, response, filterChain);

            verify(loginRateLimitService).isAllowed("192.168.1.50", "test_user");
            verify(filterChain).doFilter(request, response);
        }
    }
}