package com.zaalima.iam.controller;

import com.zaalima.iam.dto.MfaCodeRequest;
import com.zaalima.iam.service.MfaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;

    @PostMapping("/setup")
    public ResponseEntity<String> setup(
            Authentication authentication) {

        String secret =
                mfaService.generateSecret(authentication.getName());

        return ResponseEntity.ok(secret);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verify(
            @Valid @RequestBody MfaCodeRequest request,
            Authentication authentication) {

        boolean valid =
                mfaService.verifySetupCode(
                        authentication.getName(),
                        request.getCode()
                );

        if (!valid) {
            return ResponseEntity.badRequest()
                    .body("Invalid MFA code");
        }

        return ResponseEntity.ok("MFA code verified");
    }

    @PostMapping("/enable")
    public ResponseEntity<String> enable(
            Authentication authentication) {

        mfaService.enableMfa(authentication.getName());

        return ResponseEntity.ok("MFA enabled");
    }

    @PostMapping("/disable")
    public ResponseEntity<String> disable(
            Authentication authentication) {

        mfaService.disableMfa(authentication.getName());

        return ResponseEntity.ok("MFA disabled");
    }
}
