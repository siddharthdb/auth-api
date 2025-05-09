// src/main/java/com/enterprise/authapi/config/DataInitializer.java
package com.enterprise.authapi.config;

import com.enterprise.authapi.model.Permission;
import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.repository.PermissionRepository;
import com.enterprise.authapi.repository.RoleRepository;
import com.enterprise.authapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Initialize default data when the application starts
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.info("Initializing default roles and permissions");

        // Create default permissions
        Permission readPermission = createPermissionIfNotFound("READ");
        Permission writePermission = createPermissionIfNotFound("WRITE");
        Permission deletePermission = createPermissionIfNotFound("DELETE");
        Permission adminPermission = createPermissionIfNotFound("ADMIN");

        // Create default roles
        Role userRole = createRoleIfNotFound("ROLE_USER", new HashSet<>(Arrays.asList(readPermission)));
        Role moderatorRole = createRoleIfNotFound("ROLE_MODERATOR", new HashSet<>(Arrays.asList(readPermission, writePermission)));
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", new HashSet<>(Arrays.asList(readPermission, writePermission, deletePermission, adminPermission)));

        log.info("Initialized default roles and permissions");

        // Create admin user if it doesn't exist
        if (!userRepository.existsByUsername("admin")) {
            log.info("Creating default admin user");

            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@example.com");
            adminUser.setPassword(passwordEncoder.encode("admin123"));
            adminUser.setRoles(Collections.singleton(adminRole));
            adminUser.setEnabled(true);
            adminUser.setAccountNonExpired(true);
            adminUser.setAccountNonLocked(true);
            adminUser.setCredentialsNonExpired(true);

            userRepository.save(adminUser);

            log.info("Default admin user created with username: admin and password: admin123");
        }
    }

    private Permission createPermissionIfNotFound(String name) {
        return permissionRepository.findByName(name)
                .orElseGet(() -> {
                    Permission permission = new Permission();
                    permission.setName(name);
                    return permissionRepository.save(permission);
                });
    }

    private Role createRoleIfNotFound(String name, Set<Permission> permissions) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    role.setPermissions(permissions);
                    return roleRepository.save(role);
                });
    }
}