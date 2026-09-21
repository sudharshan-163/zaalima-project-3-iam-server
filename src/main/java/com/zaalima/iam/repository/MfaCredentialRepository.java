package com.zaalima.iam.repository;

import com.zaalima.iam.entity.MfaCredential;
import com.zaalima.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MfaCredentialRepository
        extends JpaRepository<MfaCredential, Long> {

    Optional<MfaCredential> findByUser(User user);

    Optional<MfaCredential> findByUserUsername(String username);
}
