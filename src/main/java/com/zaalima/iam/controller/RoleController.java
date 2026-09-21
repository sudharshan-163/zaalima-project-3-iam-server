package com.zaalima.iam.controller;

import com.zaalima.iam.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final UserService userService;

    @PostMapping("/{roleId}/authorities/{authorityId}")
    public ResponseEntity<Void> assignAuthority(
            @PathVariable Long roleId,
            @PathVariable Long authorityId) {

        userService.assignAuthorityToRole(roleId, authorityId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{roleId}/authorities/{authorityId}")
    public ResponseEntity<Void> removeAuthority(
            @PathVariable Long roleId,
            @PathVariable Long authorityId) {

        userService.removeAuthorityFromRole(roleId, authorityId);
        return ResponseEntity.noContent().build();
    }
}
