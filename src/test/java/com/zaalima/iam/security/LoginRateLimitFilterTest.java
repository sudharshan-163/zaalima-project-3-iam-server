package com.zaalima.iam.security;

import com.zaalima.iam.service.LoginRateLimitService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

    @Test
    void shouldAllowLoginWhenRateLimitAllowsRequest() throws Exception {
        when(loginRateLimitService.isAllowed("127.0.0.1", "test_user"))
                .thenReturn(true);

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
    void shouldReturn429WhenRateLimitExceeded() throws Exception {
        when(loginRateLimitService.isAllowed("127.0.0.1", "test_user"))
                .thenReturn(false);

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
    void shouldNotRateLimitGetLoginPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setRemoteAddr("127.0.0.1");

        MockHttpServletResponse response = new MockHttpServletResponse();

        loginRateLimitFilter.doFilter(request, response, filterChain);

        verifyNoInteractions(loginRateLimitService);
        verify(filterChain).doFilter(request, response);
    }
}
