// src/main/java/com/enterprise/authapi/repository/UserRoleMapRepository.java
package com.enterprise.authapi.repository;

import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.model.UserRoleMap;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for UserRoleMap entity
 */
@Repository
public interface UserRoleMapRepository extends JpaRepository<UserRoleMap, Long> {

    /**
     * Find all active role mappings for a user
     */
    List<UserRoleMap> findByUserAndActiveTrue(User user);

    /**
     * Find all role mappings for a user regardless of active status
     */
    List<UserRoleMap> findByUser(User user);

    /**
     * Find all users with a specific role that is active
     */
    List<UserRoleMap> findByRoleAndActiveTrue(Role role);

    /**
     * Find a specific user-role mapping
     */
    Optional<UserRoleMap> findByUserAndRoleAndActiveTrue(User user, Role role);

    /**
     * Deactivate a user-role mapping
     */
    @Modifying
    @Query("UPDATE UserRoleMap urm SET urm.active = false WHERE urm.user = :user AND urm.role = :role AND urm.active = true")
    int deactivateUserRole(@Param("user") User user, @Param("role") Role role);

    /**
     * Deactivate all roles for a user
     */
    @Modifying
    @Query("UPDATE UserRoleMap urm SET urm.active = false WHERE urm.user = :user AND urm.active = true")
    int deactivateAllUserRoles(@Param("user") User user);

    /**
     * Deactivate expired role mappings
     */
    @Modifying
    @Query("UPDATE UserRoleMap urm SET urm.active = false WHERE urm.expiryDate < :now AND urm.active = true")
    int deactivateExpiredRoles(@Param("now") LocalDateTime now);

    /**
     * Count users with a specific role
     */
    long countByRoleAndActiveTrue(Role role);
}