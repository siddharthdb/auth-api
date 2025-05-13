package com.enterprise.authapi.service;

import com.enterprise.authapi.exception.ResourceNotFoundException;
import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.model.UserRoleMap;
import com.enterprise.authapi.repository.RoleRepository;
import com.enterprise.authapi.repository.UserRepository;
import com.enterprise.authapi.repository.UserRoleMapRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service for managing user-role mappings
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserRoleMapService {

    private final UserRoleMapRepository userRoleMapRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    /**
     * Assign a role to a user
     *
     * @param userId the ID of the user
     * @param roleId the ID of the role
     * @param assignedBy who assigned the role
     * @param expiryDate optional expiry date for the role assignment
     * @return the created UserRoleMap
     */
    @Transactional
    public UserRoleMap assignRoleToUser(Long userId, Long roleId, String assignedBy, LocalDateTime expiryDate) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        // Check if the mapping already exists
        return userRoleMapRepository.findByUserAndRoleAndActiveTrue(user, role)
                .map(existingMap -> {
                    // Update existing mapping if needed
                    if (expiryDate != null) {
                        existingMap.setExpiryDate(expiryDate);
                    }
                    return userRoleMapRepository.save(existingMap);
                })
                .orElseGet(() -> {
                    // Create new mapping
                    UserRoleMap userRoleMap = new UserRoleMap();
                    userRoleMap.setUser(user);
                    userRoleMap.setRole(role);
                    userRoleMap.setAssignedBy(assignedBy);
                    userRoleMap.setAssignedDate(LocalDateTime.now());
                    userRoleMap.setExpiryDate(expiryDate);
                    userRoleMap.setActive(true);

                    log.info("Assigned role {} to user {} by {}", role.getName(), user.getUsername(), assignedBy);
                    return userRoleMapRepository.save(userRoleMap);
                });
    }

    /**
     * Remove a role from a user (deactivate the mapping)
     *
     * @param userId the ID of the user
     * @param roleId the ID of the role
     * @return true if the role was removed, false otherwise
     */
    @Transactional
    public boolean removeRoleFromUser(Long userId, Long roleId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        int updated = userRoleMapRepository.deactivateUserRole(user, role);

        if (updated > 0) {
            log.info("Removed role {} from user {}", role.getName(), user.getUsername());
            return true;
        }

        return false;
    }

    /**
     * Get all active roles for a user
     *
     * @param userId the ID of the user
     * @return set of roles
     */
    @Transactional(readOnly = true)
    public Set<Role> getUserRoles(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        return userRoleMapRepository.findByUserAndActiveTrue(user).stream()
                .map(UserRoleMap::getRole)
                .collect(Collectors.toSet());
    }

    /**
     * Get all users with a specific role
     *
     * @param roleId the ID of the role
     * @return list of users
     */
    @Transactional(readOnly = true)
    public List<User> getUsersByRole(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        return userRoleMapRepository.findByRoleAndActiveTrue(role).stream()
                .map(UserRoleMap::getUser)
                .collect(Collectors.toList());
    }

    /**
     * Check if a user has a specific role
     *
     * @param userId the ID of the user
     * @param roleId the ID of the role
     * @return true if the user has the role, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean hasRole(Long userId, Long roleId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        return userRoleMapRepository.findByUserAndRoleAndActiveTrue(user, role).isPresent();
    }

    /**
     * Scheduled task to deactivate expired role mappings
     */
    @Scheduled(cron = "0 0 0 * * ?") // Run at midnight every day
    @Transactional
    public void deactivateExpiredRoles() {
        int deactivated = userRoleMapRepository.deactivateExpiredRoles(LocalDateTime.now());
        if (deactivated > 0) {
            log.info("Deactivated {} expired role mappings", deactivated);
        }
    }
}