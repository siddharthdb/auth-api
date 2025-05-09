package com.enterprise.authapi.controller;

import com.enterprise.authapi.exception.ResourceNotFoundException;
import com.enterprise.authapi.model.Permission;
import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.payload.ApiResponse;
import com.enterprise.authapi.payload.RoleRequest;
import com.enterprise.authapi.repository.PermissionRepository;
import com.enterprise.authapi.repository.RoleRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Controller for managing roles and permissions
 */
@Slf4j
@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ADMIN')")  // Only admins can access role management
public class RoleController {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    /**
     * Get all roles
     *
     * @return list of all roles
     */
    @GetMapping
    public List<Role> getAllRoles() {
        log.debug("Fetching all roles");
        return roleRepository.findAll();
    }

    /**
     * Get role by ID
     *
     * @param roleId ID of role to fetch
     * @return role details
     */
    @GetMapping("/{roleId}")
    public ResponseEntity<Role> getRoleById(@PathVariable Long roleId) {
        log.debug("Fetching role with ID: {}", roleId);
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        return ResponseEntity.ok(role);
    }

    /**
     * Create a new role
     *
     * @param roleRequest role data
     * @return created role
     */
    @PostMapping
    public ResponseEntity<Role> createRole(@Valid @RequestBody RoleRequest roleRequest) {
        log.debug("Creating new role: {}", roleRequest.getName());

        if (roleRepository.findByName(roleRequest.getName()).isPresent()) {
            throw new IllegalArgumentException("Role name already exists");
        }

        Role role = new Role();
        role.setName(roleRequest.getName());

        Set<Permission> permissions = new HashSet<>();
        if (roleRequest.getPermissionIds() != null && !roleRequest.getPermissionIds().isEmpty()) {
            for (Long permissionId : roleRequest.getPermissionIds()) {
                Permission permission = permissionRepository.findById(permissionId)
                        .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));
                permissions.add(permission);
            }
        }
        role.setPermissions(permissions);

        Role createdRole = roleRepository.save(role);
        log.info("Role created successfully: {}", createdRole.getName());

        return ResponseEntity.ok(createdRole);
    }

    /**
     * Update role details
     *
     * @param roleId ID of role to update
     * @param roleRequest updated role data
     * @return updated role
     */
    @PutMapping("/{roleId}")
    public ResponseEntity<Role> updateRole(
            @PathVariable Long roleId,
            @Valid @RequestBody RoleRequest roleRequest) {

        log.debug("Updating role with ID: {}", roleId);

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        // Update role name if provided and not the same
        if (roleRequest.getName() != null && !roleRequest.getName().equals(role.getName())) {
            // Check if name already exists
            if (roleRepository.findByName(roleRequest.getName()).isPresent()) {
                throw new IllegalArgumentException("Role name already exists");
            }
            role.setName(roleRequest.getName());
        }

        // Update permissions if provided
        if (roleRequest.getPermissionIds() != null) {
            Set<Permission> permissions = new HashSet<>();
            for (Long permissionId : roleRequest.getPermissionIds()) {
                Permission permission = permissionRepository.findById(permissionId)
                        .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));
                permissions.add(permission);
            }
            role.setPermissions(permissions);
        }

        Role updatedRole = roleRepository.save(role);
        log.info("Role updated successfully: {}", updatedRole.getName());

        return ResponseEntity.ok(updatedRole);
    }

    /**
     * Delete a role
     *
     * @param roleId ID of role to delete
     * @return operation result
     */
    @DeleteMapping("/{roleId}")
    public ResponseEntity<ApiResponse> deleteRole(@PathVariable Long roleId) {
        log.debug("Deleting role with ID: {}", roleId);

        // Prevent deletion of essential roles
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        // Check if it's a system role that shouldn't be deleted
        if (role.getName().equals("ROLE_USER") || role.getName().equals("ROLE_ADMIN")) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Cannot delete system role: " + role.getName()));
        }

        roleRepository.delete(role);
        log.info("Role deleted successfully: {}", role.getName());

        return ResponseEntity.ok(new ApiResponse(true, "Role deleted successfully"));
    }

    /**
     * Get all permissions
     *
     * @return list of all permissions
     */
    @GetMapping("/permissions")
    public List<Permission> getAllPermissions() {
        log.debug("Fetching all permissions");
        return permissionRepository.findAll();
    }

    /**
     * Create a new permission
     *
     * @param permission permission data
     * @return created permission
     */
    @PostMapping("/permissions")
    public ResponseEntity<Permission> createPermission(@Valid @RequestBody Permission permission) {
        log.debug("Creating new permission: {}", permission.getName());

        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            throw new IllegalArgumentException("Permission name already exists");
        }

        Permission createdPermission = permissionRepository.save(permission);
        log.info("Permission created successfully: {}", createdPermission.getName());

        return ResponseEntity.ok(createdPermission);
    }

    /**
     * Delete a permission
     *
     * @param permissionId ID of permission to delete
     * @return operation result
     */
    @DeleteMapping("/permissions/{permissionId}")
    public ResponseEntity<ApiResponse> deletePermission(@PathVariable Long permissionId) {
        log.debug("Deleting permission with ID: {}", permissionId);

        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));

        // Check if it's a system permission that shouldn't be deleted
        if (permission.getName().equals("READ") ||
                permission.getName().equals("WRITE") ||
                permission.getName().equals("DELETE") ||
                permission.getName().equals("ADMIN")) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Cannot delete system permission: " + permission.getName()));
        }

        permissionRepository.delete(permission);
        log.info("Permission deleted successfully: {}", permission.getName());

        return ResponseEntity.ok(new ApiResponse(true, "Permission deleted successfully"));
    }
}