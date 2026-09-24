package com.zaalima.iam.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenRevocationRequest {

    @NotBlank
    private String jti;

    private long expiresAt;
}