package com.zaalima.iam.initializer;

import com.zaalima.iam.entity.Role;
import com.zaalima.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RoleInitializer implements CommandLineRunner {

    private static final String DEFAULT_ROLE = "USER";

    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) {
        if (!roleRepository.existsByName(DEFAULT_ROLE)) {
            Role role = new Role();
            role.setName(DEFAULT_ROLE);
            roleRepository.save(role);
        }
    }
}
