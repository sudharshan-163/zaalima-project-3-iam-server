package com.zaalima.iam.service;

import com.zaalima.iam.entity.MfaCredential;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.MfaCredentialRepository;
import com.zaalima.iam.repository.UserRepository;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.secret.SecretGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaServiceTest {

    @Mock
    private MfaCredentialRepository mfaCredentialRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private SecretGenerator secretGenerator;

    @Mock
    private CodeVerifier codeVerifier;

    @InjectMocks
    private MfaService mfaService;

    @Test
    void generateSecretShouldCreateAndSaveCredential() {

        User user = new User();
        user.setUsername("testuser");

        when(userRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(user));

        when(mfaCredentialRepository.findByUser(user))
                .thenReturn(Optional.empty());

        when(secretGenerator.generate())
                .thenReturn("TESTSECRET123");

        String secret = mfaService.generateSecret("testuser");

        assertEquals("TESTSECRET123", secret);

        verify(mfaCredentialRepository).save(any(MfaCredential.class));
    }

    @Test
    void verifyCodeShouldReturnTrueForValidCode() {

        MfaCredential credential = new MfaCredential();
        credential.setEnabled(true);
        credential.setSecret("TESTSECRET123");

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.of(credential));

        when(codeVerifier.isValidCode("TESTSECRET123", "123456"))
                .thenReturn(true);

        boolean result =
                mfaService.verifyCode("testuser", "123456");

        assertTrue(result);
    }

    @Test
    void verifyCodeShouldReturnFalseForInvalidCode() {

        MfaCredential credential = new MfaCredential();
        credential.setEnabled(true);
        credential.setSecret("TESTSECRET123");

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.of(credential));

        when(codeVerifier.isValidCode("TESTSECRET123", "123456"))
                .thenReturn(false);

        boolean result =
                mfaService.verifyCode("testuser", "123456");

        assertFalse(result);
    }

    @Test
    void verifyCodeShouldRejectWhenMfaIsDisabled() {

        MfaCredential credential = new MfaCredential();
        credential.setEnabled(false);
        credential.setSecret("TESTSECRET123");

        when(mfaCredentialRepository.findByUserUsername("testuser"))
                .thenReturn(Optional.of(credential));

        assertThrows(
                IllegalStateException.class,
                () -> mfaService.verifyCode("testuser", "123456")
        );
    }
}
