// src/main/java/com/enterprise/authapi/service/CustomUserDetailsService.java
package com.enterprise.authapi.service;

import com.enterprise.authapi.model.User;
import com.enterprise.authapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Custom implementation of Spring Security's UserDetailsService
 * Loads user-specific data and creates a UserDetails object that Spring Security can use for authentication and validation
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Load a user by username or email
     * This method is used by Spring Security to load the user during authentication
     *
     * @param usernameOrEmail username or email of the user
     * @return UserDetails object containing the user information
     * @throws UsernameNotFoundException if user not found with given username or email
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        // Allow login with either username or email
        User user = userRepository.findByUsername(usernameOrEmail)
                .orElseGet(() -> userRepository.findByEmail(usernameOrEmail)
                        .orElseThrow(() -> new UsernameNotFoundException(
                                "User not found with username or email: " + usernameOrEmail)));

        return user;
    }

    /**
     * Load a user by ID
     * This method is useful for loading user details in other parts of the application
     *
     * @param id the user ID
     * @return UserDetails object containing the user information
     * @throws UsernameNotFoundException if user not found with given ID
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        return user;
    }
}