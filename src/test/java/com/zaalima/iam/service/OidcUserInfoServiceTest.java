package com.zaalima.iam.service;

import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OidcUserInfoServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private OidcUserInfoService oidcUserInfoService;

    @Test
    void getUserInfo_shouldReturnExpectedClaims() {

        User user = new User();
        user.setUsername("oidctest");
        user.setEmail("oidctest@example.com");
        user.setEnabled(true);

        when(userRepository.findByUsername("oidctest"))
                .thenReturn(Optional.of(user));

        Map<String, Object> userInfo =
                oidcUserInfoService.getUserInfo("oidctest");

        assertEquals("oidctest", userInfo.get("sub"));
        assertEquals("oidctest", userInfo.get("preferred_username"));
        assertEquals(
                "oidctest@example.com",
                userInfo.get("email"));
    }

    @Test
    void getUserInfo_shouldThrowExceptionWhenUserNotFound() {

        when(userRepository.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(
                IllegalArgumentException.class,
                () -> oidcUserInfoService.getUserInfo("unknown"));
    }
}
