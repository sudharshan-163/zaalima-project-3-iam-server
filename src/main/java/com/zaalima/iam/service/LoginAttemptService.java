package com.zaalima.iam.service;

import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 5;
    public static final int LOCK_TIME_DURATION_MINUTES = 15;

    private final UserRepository userRepository;

    @Transactional
    public void loginFailed(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            int newAttempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(newAttempts);

            if (newAttempts >= MAX_ATTEMPTS) {
                user.setAccountNonLocked(false);
                user.setLockoutExpiration(LocalDateTime.now().plusMinutes(LOCK_TIME_DURATION_MINUTES));
                log.warn("User account locked due to too many failed login attempts: {}", username);
            }
            userRepository.save(user);
        });
    }

    @Transactional
    public void loginSucceeded(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            if (user.getFailedLoginAttempts() > 0 || !user.isAccountNonLocked()) {
                user.setFailedLoginAttempts(0);
                user.setAccountNonLocked(true);
                user.setLockoutExpiration(null);
                userRepository.save(user);
            }
        });
    }
}