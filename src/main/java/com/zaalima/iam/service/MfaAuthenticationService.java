package com.zaalima.iam.service;

import com.zaalima.iam.repository.MfaCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MfaAuthenticationService {

    private final MfaCredentialRepository mfaCredentialRepository;

    @Transactional(readOnly = true)
    public boolean isMfaEnabled(String username) {

        return mfaCredentialRepository
                .findByUserUsername(username)
                .map(credential -> credential.isEnabled())
                .orElse(false);
    }
}
