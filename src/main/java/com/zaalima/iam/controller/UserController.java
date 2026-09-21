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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> register(
            @Valid @RequestBody UserRegistrationRequest request) {

        UserRegistrationResponse response = userService.registerUser(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserProfileResponse> getProfile(
            @PathVariable Long id) {

        return ResponseEntity.ok(userService.getUserProfile(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserProfileResponse> updateProfile(
            @PathVariable Long id,
            @Valid @RequestBody UserProfileUpdateRequest request) {

        return ResponseEntity.ok(userService.updateUserProfile(id, request));
    }

    @GetMapping("/by-username/{username}")
    public ResponseEntity<UserProfileResponse> findByUsername(
            @PathVariable String username) {

        return ResponseEntity.ok(userService.findUserByUsername(username));
    }

    @GetMapping("/by-email/{email}")
    public ResponseEntity<UserProfileResponse> findByEmail(
            @PathVariable String email) {

        return ResponseEntity.ok(userService.findUserByEmail(email));
    }

    @PatchMapping("/{id}/enable")
    public ResponseEntity<UserProfileResponse> enableUser(
            @PathVariable Long id) {

        return ResponseEntity.ok(userService.enableUser(id));
    }

    @PatchMapping("/{id}/disable")
    public ResponseEntity<UserProfileResponse> disableUser(
            @PathVariable Long id) {

        return ResponseEntity.ok(userService.disableUser(id));
    }

    @PostMapping("/{userId}/roles/{roleId}")
    public ResponseEntity<UserProfileResponse> assignRole(
            @PathVariable Long userId,
            @PathVariable Long roleId) {

        userService.assignRoleToUser(userId, roleId); return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{userId}/roles/{roleId}")
    public ResponseEntity<UserProfileResponse> removeRole(
            @PathVariable Long userId,
            @PathVariable Long roleId) {

        userService.removeRoleFromUser(userId, roleId); return ResponseEntity.ok().build();
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        return ResponseEntity.ok(userService.createPasswordResetToken(request));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        userService.resetPassword(request);

        return ResponseEntity.noContent().build();
    }
}
