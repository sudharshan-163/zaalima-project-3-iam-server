package com.zaalima.iam.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RoleAuthorityTest {

    @Test
    void role_shouldContainAssignedAuthority() {

        Role role = new Role();
        role.setId(1L);
        role.setName("USER");

        Authority authority = new Authority();
        authority.setId(1L);
        authority.setName("READ_PROFILE");

        role.getAuthorities().add(authority);

        assertTrue(role.getAuthorities().contains(authority));
        assertEquals(1, role.getAuthorities().size());
        assertEquals("READ_PROFILE", role.getAuthorities().iterator().next().getName());
    }

    @Test
    void role_shouldSupportMultipleAuthorities() {

        Role role = new Role();
        role.setId(1L);
        role.setName("USER");

        Authority readProfile = new Authority();
        readProfile.setId(1L);
        readProfile.setName("READ_PROFILE");

        Authority updateProfile = new Authority();
        updateProfile.setId(2L);
        updateProfile.setName("UPDATE_PROFILE");

        role.getAuthorities().add(readProfile);
        role.getAuthorities().add(updateProfile);

        assertEquals(2, role.getAuthorities().size());
        assertTrue(role.getAuthorities().contains(readProfile));
        assertTrue(role.getAuthorities().contains(updateProfile));
    }

    @Test
    void user_shouldContainAssignedRole() {

        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setPassword("encoded-password");

        Role role = new Role();
        role.setId(1L);
        role.setName("USER");

        user.getRoles().add(role);

        assertTrue(user.getRoles().contains(role));
        assertEquals(1, user.getRoles().size());
        assertEquals("USER", user.getRoles().iterator().next().getName());
    }

    @Test
    void role_shouldStartWithNoAuthorities() {

        Role role = new Role();

        assertNotNull(role.getAuthorities());
        assertTrue(role.getAuthorities().isEmpty());
    }

    @Test
    void user_shouldStartWithNoRoles() {

        User user = new User();

        assertNotNull(user.getRoles());
        assertTrue(user.getRoles().isEmpty());
    }
}
