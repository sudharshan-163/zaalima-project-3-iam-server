package com.zaalima.iam.service;

import com.zaalima.iam.entity.MfaCredential;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.MfaCredentialRepository;
import com.zaalima.iam.repository.UserRepository;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final MfaCredentialRepository mfaCredentialRepository;
    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator;
    private final CodeVerifier codeVerifier;

    @Transactional
    public String generateSecret(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        MfaCredential credential =
                mfaCredentialRepository.findByUser(user)
                        .orElseGet(MfaCredential::new);

        credential.setUser(user);
        credential.setSecret(secretGenerator.generate());
        credential.setEnabled(false);
        credential.setCreatedAt(LocalDateTime.now());
        credential.setUpdatedAt(LocalDateTime.now());

        mfaCredentialRepository.save(credential);

        return credential.getSecret();
    }

    @Transactional(readOnly = true)
    public boolean verifyCode(String username, String code) {

        MfaCredential credential =
                mfaCredentialRepository.findByUserUsername(username)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "MFA is not configured"));

        if (!credential.isEnabled()) {
            throw new IllegalStateException(
                    "MFA is not enabled");
        }

        return codeVerifier.isValidCode(
                credential.getSecret(),
                code
        );
    }

    @Transactional
    public void enableMfa(String username) {

        MfaCredential credential =
                mfaCredentialRepository.findByUserUsername(username)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "MFA is not configured"));

        credential.setEnabled(true);
        credential.setUpdatedAt(LocalDateTime.now());

        mfaCredentialRepository.save(credential);
    }

    @Transactional
    public void disableMfa(String username) {

        MfaCredential credential =
                mfaCredentialRepository.findByUserUsername(username)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "MFA is not configured"));

        credential.setEnabled(false);
        credential.setUpdatedAt(LocalDateTime.now());

        mfaCredentialRepository.save(credential);
    }
}
