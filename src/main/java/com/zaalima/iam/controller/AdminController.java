package com.zaalima.iam.controller;

import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PutMapping("/users/{id}/lock")
    public ResponseEntity<Map<String, Object>> toggleUserLock(
            @PathVariable Long id,
            @RequestParam boolean locked) {
        return userRepository.findById(id).map(user -> {
            user.setAccountNonLocked(!locked);
            if (!locked) {
                user.setFailedLoginAttempts(0);
                user.setLockoutExpiration(null);
            }
            userRepository.save(user);
            return ResponseEntity.ok(Map.<String, Object>of(
                    "userId", id,
                    "locked", locked,
                    "message", locked ? "User locked successfully" : "User unlocked successfully"
            ));
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }
}