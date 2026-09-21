package com.zaalima.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class MfaCodeRequest {

    @NotBlank(message = "MFA code is required")
    @Pattern(
            regexp = "\\d{6}",
            message = "MFA code must be exactly 6 digits"
    )
    private String code;
}
