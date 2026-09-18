package com.zaalima.iam.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserRegistrationResponse {

    private Long id;
    private String username;
    private String email;
    private boolean enabled;
}
