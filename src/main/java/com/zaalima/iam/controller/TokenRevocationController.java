package com.zaalima.iam.controller;

import com.zaalima.iam.dto.TokenRevocationRequest;
import com.zaalima.iam.service.TokenRevocationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/tokens")
@RequiredArgsConstructor
public class TokenRevocationController {

    private final TokenRevocationService tokenRevocationService;

    @PostMapping("/revoke")
    public ResponseEntity<Void> revokeToken(
            @Valid @RequestBody TokenRevocationRequest request) {

        tokenRevocationService.revokeUntil(
                request.getJti(),
                request.getExpiresAt()
        );

        return ResponseEntity.noContent().build();
    }
}