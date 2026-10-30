package com.zaalima.iam.config;

import com.zaalima.iam.entity.Authority;
import com.zaalima.iam.entity.Role;
import com.zaalima.iam.entity.User;
import com.zaalima.iam.repository.AuthorityRepository;
import com.zaalima.iam.repository.RoleRepository;
import com.zaalima.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            log.info("Seeding initial IAM users and roles...");

            Authority readAuth = new Authority();
            readAuth.setName("READ");
            readAuth = authorityRepository.save(readAuth);

            Authority writeAuth = new Authority();
            writeAuth.setName("WRITE");
            writeAuth = authorityRepository.save(writeAuth);

            Role roleUser = new Role();
            roleUser.setName("ROLE_USER");
            roleUser.setAuthorities(Set.of(readAuth));
            roleRepository.save(roleUser);

            Role roleAdmin = new Role();
            roleAdmin.setName("ROLE_ADMIN");
            roleAdmin.setAuthorities(Set.of(readAuth, writeAuth));
            roleRepository.save(roleAdmin);

            User regularUser = new User();
            regularUser.setUsername("user");
            regularUser.setEmail("user@zaalima.com");
            regularUser.setPassword(passwordEncoder.encode("Password@123"));
            regularUser.setEnabled(true);
            regularUser.setAccountNonLocked(true);
            regularUser.setRoles(Set.of(roleUser));
            userRepository.save(regularUser);

            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@zaalima.com");
            adminUser.setPassword(passwordEncoder.encode("Admin@123"));
            adminUser.setEnabled(true);
            adminUser.setAccountNonLocked(true);
            adminUser.setRoles(Set.of(roleAdmin));
            userRepository.save(adminUser);

            log.info("Default users seeded: user / Password@123 and admin / Admin@123");
        }
    }
}