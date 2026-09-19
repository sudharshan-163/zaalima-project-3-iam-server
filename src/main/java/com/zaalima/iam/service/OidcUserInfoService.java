package com.zaalima.iam.service;

import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public Map<String, Object> getUserInfo(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "User not found: " + username));

        return Map.of(
                "sub", user.getUsername(),
                "preferred_username", user.getUsername(),
                "email", user.getEmail()
        );
    }
}
