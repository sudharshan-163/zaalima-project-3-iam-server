package com.zaalima.iam.repository;

import com.zaalima.iam.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {

    Optional<Authority> findByName(String name);

    boolean existsByName(String name);
}
