package com.enterprise.authapi.controller;

import com.enterprise.authapi.exception.ResourceNotFoundException;
import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.payload.ApiResponse;
import com.enterprise.authapi.payload.UpdatePasswordRequest;
import com.enterprise.authapi.payload.UpdateProfileRequest;
import com.enterprise.authapi.payload.UserSummary;
import com.enterprise.authapi.repository.RoleRepository;
import com.enterprise.authapi.repository.UserRepository;
import com.enterprise.authapi.security.CurrentUser;
import com.enterprise.authapi.service.RefreshTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for managing user accounts
 */
@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    /**
     * Get all users (admin only)
     *
     * @return list of all users
     */
    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<UserSummary> getAllUsers() {
        log.debug("Fetching all users");
        return userRepository.findAll().stream()
                .map(this::convertToUserSummary)
                .collect(Collectors.toList());
    }

    /**
     * Get user by ID (admin or self)
     *
     * @param userId ID of user to fetch
     * @return user details
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasAuthority('ADMIN') or @userSecurity.isCurrentUserId(#userId)")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long userId) {
        log.debug("Fetching user with ID: {}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        return ResponseEntity.ok(convertToUserSummary(user));
    }

    /**
     * Update user profile
     *
     * @param userId ID of user to update
     * @param updateRequest profile data to update
     * @return updated user details
     */
    @PutMapping("/{userId}")
    @PreAuthorize("hasAuthority('ADMIN') or @userSecurity.isCurrentUserId(#userId)")
    public ResponseEntity<?> updateUser(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateProfileRequest updateRequest) {

        log.debug("Updating profile for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        boolean isEmailChanged = false;
        if (updateRequest.getEmail() != null && !updateRequest.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(updateRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse(false, "Email is already in use"));
            }
            user.setEmail(updateRequest.getEmail());
            isEmailChanged = true;
        }

        if (updateRequest.getFirstName() != null) {
            user.setFirstName(updateRequest.getFirstName());
        }

        if (updateRequest.getLastName() != null) {
            user.setLastName(updateRequest.getLastName());
        }

        if (updateRequest.getPhoneNumber() != null) {
            user.setPhoneNumber(updateRequest.getPhoneNumber());
        }

        User updatedUser = userRepository.save(user);

        if (isEmailChanged) {
            // If email changed, consider forcing re-authentication for security
            log.info("Email changed for user ID: {}. Revoking all refresh tokens.", userId);
            refreshTokenService.revokeAllUserTokens(user);
        }

        return ResponseEntity.ok(convertToUserSummary(updatedUser));
    }

    /**
     * Update user password
     *
     * @param userId ID of user to update
     * @param updateRequest password update data
     * @return operation result
     */
    @PutMapping("/{userId}/password")
    @PreAuthorize("@userSecurity.isCurrentUserId(#userId)")
    public ResponseEntity<?> updatePassword(
            @PathVariable Long userId,
            @Valid @RequestBody UpdatePasswordRequest updateRequest) {

        log.debug("Updating password for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        // Verify current password
        if (!passwordEncoder.matches(updateRequest.getCurrentPassword(), user.getPassword())) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Current password is incorrect"));
        }

        // Update to new password
        user.setPassword(passwordEncoder.encode(updateRequest.getNewPassword()));
        userRepository.save(user);

        // For security, revoke all refresh tokens when password changes
        refreshTokenService.revokeAllUserTokens(user);

        log.info("Password updated successfully for user ID: {}. All refresh tokens revoked.", userId);

        return ResponseEntity.ok(new ApiResponse(true, "Password updated successfully"));
    }

    /**
     * Update user roles (admin only)
     *
     * @param userId ID of user to update
     * @param roleIds list of role IDs to assign
     * @return updated user details
     */
    @PutMapping("/{userId}/roles")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> updateUserRoles(
            @PathVariable Long userId,
            @RequestBody List<Long> roleIds) {

        log.debug("Updating roles for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Set<Role> roles = new HashSet<>();
        for (Long roleId : roleIds) {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));
            roles.add(role);
        }

        user.setRoles(roles);
        User updatedUser = userRepository.save(user);

        // For security, revoke all refresh tokens when roles change
        refreshTokenService.revokeAllUserTokens(user);

        log.info("Roles updated for user ID: {}. All refresh tokens revoked.", userId);

        return ResponseEntity.ok(convertToUserSummary(updatedUser));
    }

    /**
     * Delete a user account
     *
     * @param userId ID of user to delete
     * @return operation result
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('ADMIN') or @userSecurity.isCurrentUserId(#userId)")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        log.debug("Deleting user with ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        // Delete all refresh tokens first
        refreshTokenService.deleteByUserId(userId);

        // Delete user
        userRepository.delete(user);

        log.info("User deleted successfully: ID {}", userId);

        return ResponseEntity.ok(new ApiResponse(true, "User deleted successfully"));
    }

    /**
     * Helper method to convert User entity to UserSummary DTO
     */
    private UserSummary convertToUserSummary(User user) {
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new UserSummary(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles
        );
    }
}