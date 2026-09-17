package com.zaalima.iam.service;

import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserProfileUpdateRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.exception.DuplicateEmailException;
import com.zaalima.iam.exception.DuplicateUsernameException;
import com.zaalima.iam.exception.UserNotFoundException;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String DEFAULT_ROLE = "USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException("Email already exists");
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE)
            .orElseThrow(() -> new IllegalStateException("Default USER role not found"));

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        user.getRoles().add(defaultRole);

        User savedUser = userRepository.save(user);

        return new UserRegistrationResponse(
            savedUser.getId(),
            savedUser.getUsername(),
            savedUser.getEmail(),
            savedUser.isEnabled()
        );
    }

    public UserProfileResponse getUserProfile(Long userId) {

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        return new UserProfileResponse(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.isEnabled()
        );
    }

    public UserProfileResponse updateUserProfile(
            Long userId,
            UserProfileUpdateRequest request) {

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!user.getUsername().equals(request.getUsername())
                && userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException("Username already exists");
        }

        if (!user.getEmail().equals(request.getEmail())
                && userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException("Email already exists");
        }

        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        User updatedUser = userRepository.save(user);

        return new UserProfileResponse(
            updatedUser.getId(),
            updatedUser.getUsername(),
            updatedUser.getEmail(),
            updatedUser.isEnabled()
        );
    }
}
