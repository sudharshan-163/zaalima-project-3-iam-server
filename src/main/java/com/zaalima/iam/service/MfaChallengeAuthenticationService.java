package com.zaalima.iam.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MfaChallengeAuthenticationService {

    private final MfaChallengeService mfaChallengeService;
    private final MfaService mfaService;

    public boolean verifyChallenge(String username, String code) {

        if (!mfaChallengeService.hasValidChallenge(username)) {
            return false;
        }

        boolean valid = mfaService.verifyCode(username, code);

        if (valid) {
            mfaChallengeService.removeChallenge(username);
        }

        return valid;
    }
}
