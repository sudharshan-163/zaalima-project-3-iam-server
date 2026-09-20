package com.zaalima.iam.controller;

import com.zaalima.iam.dto.ForgotPasswordRequest;
import com.zaalima.iam.dto.ResetPasswordRequest;
import com.zaalima.iam.dto.UserProfileResponse;
import com.zaalima.iam.dto.UserProfileUpdateRequest;
import com.zaalima.iam.dto.UserRegistrationRequest;
import com.zaalima.iam.dto.UserRegistrationResponse;
import com.zaalima.iam.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> register(
            @Valid @RequestBody UserRegistrationRequest request) {

        UserRegistrationResponse response =
                userService.registerUser(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserProfileResponse> getProfile(
            @PathVariable Long id) {

        UserProfileResponse response =
                userService.getUserProfile(id);

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserProfileResponse> updateProfile(
            @PathVariable Long id,
            @Valid @RequestBody UserProfileUpdateRequest request) {

        UserProfileResponse response =
                userService.updateUserProfile(id, request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        String token =
                userService.createPasswordResetToken(request.email());

        return ResponseEntity.ok(
                Map.of(
                        "message", "Password reset token generated",
                        "token", token
                )
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        userService.resetPassword(
                request.token(),
                request.newPassword()
        );

        return ResponseEntity.ok(
                Map.of("message", "Password reset successful")
        );
    }
}
