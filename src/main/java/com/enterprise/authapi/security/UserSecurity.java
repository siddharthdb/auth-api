package com.enterprise.authapi.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Security helper for user-related operations
 * Used in PreAuthorize annotations for custom security checks
 */
@Component("userSecurity")
public class UserSecurity {

    /**
     * Check if the authenticated user is the user with the given ID
     *
     * @param userId user ID to check
     * @return true if authenticated user has the given ID
     */
    public boolean isCurrentUserId(Long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof UserPrincipal) {
            return ((UserPrincipal) principal).getId().equals(userId);
        }

        return false;
    }
}